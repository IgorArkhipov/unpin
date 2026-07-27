use crate::{
    approval::{ControlApprovalContext, ControlAuthorization},
    mutation::{
        BackupAuthenticationKey, NativeToggleControlError, NativeTogglePlan, TogglePlanInput,
        ToggleResult, apply_authorized_toggle_transaction_with_policy,
    },
    sessions::SessionAuthorityKey,
    transitions::TransitionRecoveryPolicy,
};

pub(crate) fn apply_group_member_toggle(
    app_state_root: std::path::PathBuf,
    reviewed: &NativeTogglePlan,
    authorization: &ControlAuthorization,
    context: &ControlApprovalContext,
    backup_authentication_key: BackupAuthenticationKey,
    session_authority_key: SessionAuthorityKey,
) -> Result<ToggleResult, NativeToggleControlError> {
    let expectation = reviewed.approval_expectation(context)?;
    authorization.assert_matches(&expectation)?;
    Ok(apply_authorized_toggle_transaction_with_policy(
        TogglePlanInput {
            app_state_root,
            item: reviewed.preview.selection.clone(),
            apply: true,
            backup_authentication_key: Some(backup_authentication_key),
            session_authority_key: Some(session_authority_key),
        },
        &reviewed.transition,
        authorization,
        &reviewed.preview,
        TransitionRecoveryPolicy::NoResumeWrites,
    ))
}
