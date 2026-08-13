use std::fs;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        CONTROL_APPROVAL_AUDIENCE, CONTROL_APPROVAL_ISSUER, ControlApprovalContext,
        ControlAuthorization, authorize_control,
    },
    mutation::BackupAuthenticationKey,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration},
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowDefinition, WorkflowDefinitionAction,
        WorkflowDefinitionApplyStatus, WorkflowDefinitionControlError,
        WorkflowDefinitionController, WorkflowDefinitionDisposition, WorkflowDefinitionErrorClass,
        WorkflowDefinitionHistoryLifecycle, WorkflowDefinitionHistoryRecord,
        WorkflowDefinitionMutationRequest, WorkflowDefinitionPlan, WorkflowModeDefinition,
        WorkflowStore,
    },
};

fn definition() -> WorkflowDefinition {
    WorkflowDefinition {
        version: WORKFLOW_DEFINITION_VERSION,
        id: "delivery".to_string(),
        display_name: "Delivery".to_string(),
        description: Some("planning and implementation workflow".to_string()),
        baseline_profile_id: "baseline".to_string(),
        entry_mode: "planning".to_string(),
        modes: vec![WorkflowModeDefinition::new("planning", "baseline")],
    }
}

fn approval_context() -> ControlApprovalContext {
    ControlApprovalContext::new("repository", "workspace").expect("approval context")
}

fn authorization(
    app_state_root: &std::path::Path,
    plan: &WorkflowDefinitionPlan,
    suffix: &str,
) -> ControlAuthorization {
    let expectation = plan
        .approval_expectation(&approval_context())
        .expect("approval expectation");
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
            receipt_id: format!("workflow-receipt-{suffix}"),
            nonce: format!("workflow-nonce-{suffix}"),
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
        OwnerGeneration::new("workflow-approval-test", 1).expect("approval owner"),
    )
    .expect("authorize workflow definition control")
}

#[test]
fn controller_applies_retries_no_ops_deletes_and_restores_authenticated_history() {
    let temp = TempDir::new().expect("temporary app state");
    let root = temp.path().canonicalize().expect("canonical app state");
    let key = BackupAuthenticationKey::new([0x42; 32]);
    let controller =
        WorkflowDefinitionController::with_backup_authentication_key(&root, key.clone());
    let context = approval_context();
    let definition = definition();

    let upsert = controller
        .plan(
            WorkflowDefinitionMutationRequest::upsert(definition.clone()),
            &context,
        )
        .expect("upsert plan");
    assert_eq!(upsert.action, WorkflowDefinitionAction::Upsert);
    assert_eq!(
        upsert.disposition,
        WorkflowDefinitionDisposition::Actionable
    );
    let applied = controller
        .apply(&upsert, authorization(&root, &upsert, "upsert"), &context)
        .expect("apply upsert");
    assert_eq!(applied.status, WorkflowDefinitionApplyStatus::Applied);
    assert!(!applied.cached);
    let upsert_history_id = applied.history_id.expect("upsert history");

    let retried = controller
        .apply(
            &upsert,
            authorization(&root, &upsert, "upsert-retry"),
            &context,
        )
        .expect("exact retry");
    assert!(retried.cached);
    assert_eq!(
        retried.history_id.as_deref(),
        Some(upsert_history_id.as_str())
    );

    let no_op = controller
        .plan(
            WorkflowDefinitionMutationRequest::upsert(definition.clone()),
            &context,
        )
        .expect("no-op plan");
    assert_eq!(no_op.disposition, WorkflowDefinitionDisposition::NoOp);
    let no_op_result = controller
        .apply(&no_op, authorization(&root, &no_op, "no-op"), &context)
        .expect("apply no-op");
    assert_eq!(no_op_result.status, WorkflowDefinitionApplyStatus::NoOp);
    assert_eq!(controller.history().expect("history").len(), 1);

    let delete = controller
        .plan(
            WorkflowDefinitionMutationRequest::delete("delivery"),
            &context,
        )
        .expect("delete plan");
    let deleted = controller
        .apply(&delete, authorization(&root, &delete, "delete"), &context)
        .expect("apply delete");
    let delete_history_id = deleted.history_id.expect("delete history");
    assert!(
        WorkflowStore::new(&root)
            .load_global_definition("delivery")
            .expect("load deleted workflow")
            .is_none()
    );

    let restore = controller
        .plan(
            WorkflowDefinitionMutationRequest::restore(&delete_history_id),
            &context,
        )
        .expect("restore plan");
    assert_eq!(restore.action, WorkflowDefinitionAction::Restore);
    let restored = controller
        .apply(
            &restore,
            authorization(&root, &restore, "restore"),
            &context,
        )
        .expect("apply restore");
    assert_eq!(restored.definition, Some(definition.clone()));
    assert_eq!(
        WorkflowStore::new(&root)
            .load_global_definition("delivery")
            .expect("load restored workflow")
            .expect("restored workflow")
            .value,
        definition
    );
    assert_eq!(controller.history().expect("history").len(), 3);
}

#[test]
fn controller_requires_keys_revalidates_drift_and_refuses_unowned_absent_delete() {
    let temp = TempDir::new().expect("temporary app state");
    let root = temp.path().canonicalize().expect("canonical app state");
    let key = BackupAuthenticationKey::new([0x42; 32]);
    let controller =
        WorkflowDefinitionController::with_backup_authentication_key(&root, key.clone());
    let context = approval_context();
    let definition = definition();
    let plan = controller
        .plan(
            WorkflowDefinitionMutationRequest::upsert(definition.clone()),
            &context,
        )
        .expect("upsert plan");

    let missing_key = WorkflowDefinitionController::new(&root)
        .apply(&plan, authorization(&root, &plan, "missing-key"), &context)
        .expect_err("actionable apply needs authenticated history");
    assert!(matches!(
        missing_key,
        WorkflowDefinitionControlError::BackupAuthenticationRequired
    ));
    assert_eq!(missing_key.class(), WorkflowDefinitionErrorClass::Blocked);

    let mut drifted = definition.clone();
    drifted.display_name = "Drifted".to_string();
    AtomicJsonStore::new(root.join("workflows/delivery.json"), 1)
        .compare_and_swap(
            None,
            OwnerGeneration::new("outside-writer", 1).expect("outside owner"),
            &drifted,
        )
        .expect("write drifted definition");
    let drift = controller
        .apply(&plan, authorization(&root, &plan, "drift"), &context)
        .expect_err("reviewed pre-state drift must block");
    assert!(matches!(drift, WorkflowDefinitionControlError::PlanDrift));
    assert_eq!(drift.class(), WorkflowDefinitionErrorClass::ReplanRequired);

    let delete = controller
        .plan(
            WorkflowDefinitionMutationRequest::delete("delivery"),
            &context,
        )
        .expect("delete plan");
    let mut changed_after_review = definition.clone();
    changed_after_review.display_name = "Changed after delete review".to_string();
    AtomicJsonStore::new(root.join("workflows/delivery.json"), 1)
        .compare_and_swap(
            delete.expected_revision.as_ref(),
            OwnerGeneration::new("outside-writer", 2).expect("outside owner"),
            &changed_after_review,
        )
        .expect("change reviewed delete state");
    let delete_drift = controller
        .apply(
            &delete,
            authorization(&root, &delete, "delete-drift"),
            &context,
        )
        .expect_err("delete must revalidate reviewed state");
    assert!(matches!(
        delete_drift,
        WorkflowDefinitionControlError::PlanDrift
    ));

    let absent_delete = controller
        .plan(
            WorkflowDefinitionMutationRequest::delete("unknown"),
            &context,
        )
        .expect_err("absent delete has no ownership tombstone");
    assert!(matches!(
        absent_delete,
        WorkflowDefinitionControlError::OwnershipEvidenceRequired(id) if id == "unknown"
    ));
}

#[test]
fn controller_rejects_tampered_authenticated_history_as_recovery_required() {
    let temp = TempDir::new().expect("temporary app state");
    let root = temp.path().canonicalize().expect("canonical app state");
    let controller = WorkflowDefinitionController::with_backup_authentication_key(
        &root,
        BackupAuthenticationKey::new([0x42; 32]),
    );
    let context = approval_context();
    let plan = controller
        .plan(
            WorkflowDefinitionMutationRequest::upsert(definition()),
            &context,
        )
        .expect("upsert plan");
    let result = controller
        .apply(
            &plan,
            authorization(&root, &plan, "tamper-source"),
            &context,
        )
        .expect("apply upsert");
    let history_id = result.history_id.expect("history id");
    let history_path = root
        .join("workflows/history")
        .join(format!("{history_id}.json"));
    let raw = fs::read_to_string(&history_path).expect("read history");
    fs::write(&history_path, raw.replace("Delivery", "Tampered")).expect("tamper history");

    let error = controller
        .plan(
            WorkflowDefinitionMutationRequest::restore(&history_id),
            &context,
        )
        .expect_err("tampered history must not restore");
    assert_eq!(
        error.class(),
        WorkflowDefinitionErrorClass::RecoveryRequired
    );
}

#[test]
fn controller_resumes_an_authenticated_prepared_history_interruption() {
    let temp = TempDir::new().expect("temporary app state");
    let root = temp.path().canonicalize().expect("canonical app state");
    let backup_key = BackupAuthenticationKey::new([0x42; 32]);
    let controller =
        WorkflowDefinitionController::with_backup_authentication_key(&root, backup_key.clone());
    let context = approval_context();
    let plan = controller
        .plan(
            WorkflowDefinitionMutationRequest::upsert(definition()),
            &context,
        )
        .expect("upsert plan");
    let history_id = format!("workflow-history-{}", &plan.plan_fingerprint[..32]);
    let mut prepared_record = WorkflowDefinitionHistoryRecord {
        schema_version: 1,
        history_id: history_id.clone(),
        operation_id: plan.operation_id.clone(),
        plan_fingerprint: plan.plan_fingerprint.clone(),
        action: plan.action,
        lifecycle: WorkflowDefinitionHistoryLifecycle::Prepared,
        workflow_id: plan.workflow_id.clone(),
        repository_key: plan.repository_key.clone(),
        workspace_key: plan.workspace_key.clone(),
        source_history_id: plan.source_history_id.clone(),
        definition_before: plan.definition_before.clone(),
        revision_before: plan.expected_revision.clone(),
        owner_before: plan.expected_owner.clone(),
        definition_after: plan.definition_after.clone(),
        revision_after: None,
        owner_after: None,
        authentication_key_id: backup_key.key_id(),
        integrity_digest: String::new(),
    };
    let payload = serde_json::to_vec(&prepared_record).expect("serialize unsigned history");
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&[0x42; 32])
        .expect("history HMAC key");
    mac.update(b"unpin-workflow-definition-history-v1\0");
    mac.update(&payload);
    prepared_record.integrity_digest = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    prepared_record
        .verify(&backup_key)
        .expect("verify prepared history fixture");
    AtomicJsonStore::new(
        root.join("workflows/history")
            .join(format!("{history_id}.json")),
        1,
    )
    .compare_and_swap(
        None,
        OwnerGeneration::new(plan.operation_id.clone(), 1).expect("history owner"),
        &prepared_record,
    )
    .expect("prepare authenticated history without mutation");

    assert!(
        WorkflowStore::new(&root)
            .load_global_definition("delivery")
            .expect("load definition before resume")
            .is_none()
    );
    let prepared = fs::read_to_string(
        root.join("workflows/history")
            .join(format!("{history_id}.json")),
    )
    .expect("read prepared history");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&prepared).expect("prepared history JSON")["value"]
            ["lifecycle"],
        "prepared"
    );

    let result = controller
        .apply(
            &plan,
            authorization(&root, &plan, "prepared-resume"),
            &context,
        )
        .expect("resume prepared history");
    assert_eq!(result.status, WorkflowDefinitionApplyStatus::Applied);
    assert_eq!(result.history_id.as_deref(), Some(history_id.as_str()));
    assert_eq!(result.definition, Some(definition()));
    let committed = fs::read_to_string(
        root.join("workflows/history")
            .join(format!("{history_id}.json")),
    )
    .expect("read committed history");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&committed).expect("committed history JSON")["value"]
            ["lifecycle"],
        "committed"
    );
}
