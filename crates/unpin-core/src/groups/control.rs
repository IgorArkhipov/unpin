use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use crate::{
    approval::{ApprovalExpectation, ControlApprovalContext, ControlAuthorization},
    discovery::discover_all,
    groups::{
        GroupApplyMemberResult, GroupApplyMemberStatus, GroupApplyResult,
        GroupCohortBackupCoverageV1, GroupCohortBackupIndexV1, GroupDiscoveryIndex,
        GroupExecutionCohort, GroupMemberIdentity, GroupMemberPlanOutcome,
        GroupOperationAuthorizationLink, GroupOperationError, GroupOperationLifecycle,
        GroupOperationRecord, GroupOperationStore, GroupPlanDisposition, GroupPlanError,
        GroupPlanMode, GroupPlanner, GroupRef, GroupState, GroupTargetState, GroupTogglePlan,
        acquire_group_definition_lock, index_discovery, index_source_views,
        shared_source_has_unlisted_view,
    },
    mutation::{
        BackupAuthenticationKey, NativeToggleController, ToggleStatus,
        authenticated_backup_manifest_digest, group_control::apply_group_member_toggle,
    },
    sessions::SessionAuthorityKey,
    state::atomic_json::{OwnerGeneration, StateError, StateResourceLock, StateSnapshot},
    transitions::{
        EffectCheckpointStatus, JournalError, TransitionJournal, TransitionJournalStore,
        TransitionKind,
    },
};

#[derive(Debug, Clone)]
pub struct GroupController {
    planner: GroupPlanner,
    backup_authentication_key: BackupAuthenticationKey,
    session_authority_key: SessionAuthorityKey,
}

struct CohortApplyContext<'a, 'discovery> {
    reviewed: &'a GroupTogglePlan,
    authorization: &'a ControlAuthorization,
    parent_expectation: &'a ApprovalExpectation,
    approval_context: &'a ControlApprovalContext,
    discovery: &'a GroupDiscoveryIndex<'discovery>,
    selected: &'a BTreeSet<GroupMemberIdentity>,
    source_views: &'a BTreeMap<String, BTreeSet<GroupMemberIdentity>>,
    journals: &'a [TransitionJournal],
}

impl GroupController {
    #[must_use]
    pub fn new(
        planner: GroupPlanner,
        backup_authentication_key: BackupAuthenticationKey,
        session_authority_key: SessionAuthorityKey,
    ) -> Self {
        Self {
            planner,
            backup_authentication_key,
            session_authority_key,
        }
    }

    pub fn plan(
        &self,
        reference: &GroupRef,
        target: GroupTargetState,
        max_members: usize,
        mode: GroupPlanMode,
    ) -> Result<GroupTogglePlan, GroupControlError> {
        self.planner
            .plan(reference, target, max_members, mode)
            .map_err(Into::into)
    }

    pub(crate) fn seal_authorizing_operation(
        &self,
        reviewed: &GroupTogglePlan,
        authorization_decision_digest: &str,
        authorization_link: GroupOperationAuthorizationLink,
    ) -> Result<(), GroupControlError> {
        reviewed.verify()?;
        if reviewed.disposition != GroupPlanDisposition::Actionable
            || authorization_decision_digest.len() != 64
            || !crate::is_lower_hex_digest(authorization_decision_digest)
        {
            return Err(GroupControlError::InvalidPlan);
        }
        let operation_id = reviewed
            .operation_id
            .as_ref()
            .ok_or(GroupControlError::InvalidPlan)?;
        let approval_context = ControlApprovalContext::new(
            self.planner.resolver().context().repository_key(),
            self.planner.resolver().context().workspace_key(),
        )
        .map_err(|error| GroupControlError::ApprovalContext(error.to_string()))?;
        reviewed.approval_expectation_verified(&approval_context)?;
        let app_state_root = self.planner.resolver().context().app_state_root();
        let _execution_lock = acquire_operation_execution_lock(app_state_root, operation_id)?;
        let store = GroupOperationStore::new(
            app_state_root.to_path_buf(),
            self.backup_authentication_key.clone(),
        );
        if let Some(mut existing) = store.load(operation_id)? {
            if operation_matches(
                &existing.value,
                reviewed,
                &approval_context,
                authorization_decision_digest,
            ) && existing.value.authorization_link.as_ref() == Some(&authorization_link)
            {
                return Ok(());
            }
            if operation_scope_matches(&existing.value, reviewed, &approval_context)
                && !existing.value.provider_writes_started
                && existing.value.terminal_result.is_none()
            {
                existing.value.authorization_decision_digest =
                    authorization_decision_digest.to_string();
                existing.value.authorization_link = Some(authorization_link);
                store.save(
                    &existing.value,
                    &existing.revision,
                    operation_owner(operation_id)?,
                )?;
                return Ok(());
            }
            return Err(GroupControlError::InvalidPlan);
        }
        let definition_name = GroupRef::parse(&reviewed.qualified_name)
            .map_err(GroupPlanError::from)?
            .name;
        let _definition_lock = acquire_group_definition_lock(
            self.planner.resolver().context(),
            reviewed.scope,
            &[&definition_name],
        )?;
        let revalidated = self.planner.revalidate(reviewed)?;
        if revalidated.plan_fingerprint != reviewed.plan_fingerprint {
            return Err(GroupControlError::PlanDrift);
        }
        let operation = GroupOperationRecord::in_progress(
            reviewed.clone(),
            authorization_decision_digest.to_string(),
            Some(authorization_link),
            approval_context.repository_key().to_string(),
            approval_context.workspace_key().to_string(),
        )?;
        store.create(&operation, operation_owner(operation_id)?)?;
        Ok(())
    }

    pub fn apply(
        &self,
        reviewed: &GroupTogglePlan,
        authorization: ControlAuthorization,
    ) -> Result<GroupApplyResult, GroupControlError> {
        reviewed.verify()?;
        if reviewed.disposition != GroupPlanDisposition::Actionable {
            return Err(GroupControlError::NotActionable);
        }
        let operation_id = reviewed
            .operation_id
            .as_ref()
            .ok_or(GroupControlError::InvalidPlan)?;
        let approval_context = ControlApprovalContext::new(
            self.planner.resolver().context().repository_key(),
            self.planner.resolver().context().workspace_key(),
        )
        .map_err(|error| GroupControlError::ApprovalContext(error.to_string()))?;
        let expectation = reviewed.approval_expectation_verified(&approval_context)?;
        authorization.assert_matches(&expectation)?;
        let app_state_root = self.planner.resolver().context().app_state_root();
        let _execution_lock = acquire_operation_execution_lock(app_state_root, operation_id)?;

        let store = GroupOperationStore::new(
            app_state_root.to_path_buf(),
            self.backup_authentication_key.clone(),
        );
        let owner = operation_owner(operation_id)?;
        let existing = store.load(operation_id)?;
        if let Some(existing) = existing.as_ref()
            && (existing.value.terminal_result.is_some() || existing.value.provider_writes_started)
        {
            return self.existing_result(
                &store,
                existing.clone(),
                reviewed,
                &approval_context,
                None,
                owner,
            );
        }

        let definition_name = GroupRef::parse(&reviewed.qualified_name)
            .map_err(GroupPlanError::from)?
            .name;
        let definition_lock = acquire_group_definition_lock(
            self.planner.resolver().context(),
            reviewed.scope,
            &[&definition_name],
        )?;
        let revalidated = self.planner.revalidate(reviewed)?;
        if revalidated.plan_fingerprint != reviewed.plan_fingerprint {
            return Err(GroupControlError::PlanDrift);
        }

        let (mut operation, mut operation_revision) = if let Some(existing) = existing {
            if !operation_matches(
                &existing.value,
                reviewed,
                &approval_context,
                authorization.decision_digest(),
            ) {
                return Err(GroupControlError::InvalidPlan);
            }
            (existing.value, existing.revision)
        } else {
            let operation = GroupOperationRecord::in_progress(
                reviewed.clone(),
                authorization.decision_digest().to_string(),
                None,
                approval_context.repository_key().to_string(),
                approval_context.workspace_key().to_string(),
            )?;
            let revision = store.create(&operation, owner.clone())?;
            (operation, revision)
        };
        let sealed_revalidation = self.planner.revalidate(reviewed)?;
        if sealed_revalidation.plan_fingerprint != reviewed.plan_fingerprint {
            let result = prewrite_drift_result(reviewed);
            operation.terminalize(result)?;
            store.save(&operation, &operation_revision, owner)?;
            return Err(GroupControlError::PlanDrift);
        }
        drop(definition_lock);
        operation.mark_provider_writes_started()?;
        operation_revision = store.save(&operation, &operation_revision, owner.clone())?;

        let mut member_results = initial_member_results(reviewed);
        let mut aggregate_backup_ids = BTreeSet::new();
        let execution_inputs =
            match discover_all(self.planner.resolver().context().discovery_roots()) {
                Ok(discovery) => {
                    NativeToggleController::new(self.planner.resolver().context().app_state_root())
                        .planning_journals()
                        .map(|journals| (discovery, journals))
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            };
        let discovery_index = execution_inputs
            .as_ref()
            .ok()
            .map(|(discovery, _)| index_discovery(discovery));
        let source_views = execution_inputs
            .as_ref()
            .ok()
            .map(|(discovery, _)| index_source_views(&discovery.items));
        let selected = reviewed
            .members
            .iter()
            .map(|member| member.identity.clone())
            .collect::<BTreeSet<_>>();
        for cohort in &reviewed.cohorts {
            match (&execution_inputs, &discovery_index, &source_views) {
                (Ok((_, journals)), Some(discovery), Some(source_views)) => self.apply_cohort(
                    cohort,
                    &CohortApplyContext {
                        reviewed,
                        authorization: &authorization,
                        parent_expectation: &expectation,
                        approval_context: &approval_context,
                        discovery,
                        selected: &selected,
                        source_views,
                        journals,
                    },
                    &mut member_results,
                ),
                (Err(error), _, _) => mark_cohort_failed(cohort, &mut member_results, error),
                _ => unreachable!("discovery index exists for successful execution inputs"),
            }
            let coverage = cohort_backup_coverage(reviewed, cohort, &member_results);
            normalize_cohort_member_backup_ids(reviewed, cohort, &coverage, &mut member_results);
            let backup_ids = coverage
                .iter()
                .map(|item| item.backup_id.clone())
                .collect::<Vec<_>>();
            if !backup_ids.is_empty() {
                aggregate_backup_ids.extend(backup_ids.iter().cloned());
                let index = match GroupCohortBackupIndexV1::new(
                    operation_id.clone(),
                    cohort.cohort_id.clone(),
                    cohort
                        .member_indices
                        .iter()
                        .map(|index| reviewed.members[*index].identity.clone())
                        .collect(),
                    cohort.resource_ids.clone(),
                    coverage,
                    &self.backup_authentication_key,
                ) {
                    Ok(index) => index,
                    Err(error) => {
                        mark_cohort_recovery_required(
                            cohort,
                            &mut member_results,
                            &format!("cohort backup evidence failed: {error}"),
                        );
                        continue;
                    }
                };
                if let Err(error) = store.save_backup_index(&index, owner.clone()) {
                    mark_cohort_recovery_required(
                        cohort,
                        &mut member_results,
                        &format!("cohort backup evidence failed: {error}"),
                    );
                    continue;
                }
            }
        }
        if member_results.iter().any(|member| {
            member.failure_mode == Some(crate::groups::GroupMemberFailureMode::RecoveryRequired)
        }) {
            for member in &mut member_results {
                if member.status == GroupApplyMemberStatus::Failed
                    && member.failure_mode.is_none()
                    && member.reason.is_none()
                {
                    member.reason =
                        Some("operation-blocked: another cohort requires recovery".to_string());
                }
            }
        }

        let lifecycle = roll_up(&member_results);
        let (final_state, observation_fresh, observation_reason) =
            self.observe_final_state(reviewed);
        let result = GroupApplyResult {
            operation_id: operation_id.clone(),
            qualified_name: reviewed.qualified_name.clone(),
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            requested_state: reviewed.target,
            lifecycle,
            members: member_results,
            backup_ids: aggregate_backup_ids.into_iter().collect(),
            final_state,
            observation_fresh,
            observation_reason,
        };
        operation.terminalize(result.clone())?;
        store.save(&operation, &operation_revision, owner)?;
        Ok(result)
    }

    pub fn status(
        &self,
        reviewed: &GroupTogglePlan,
        authorization_decision_digest: &str,
    ) -> Result<GroupApplyResult, GroupControlError> {
        self.status_with_expected_decision(reviewed, Some(authorization_decision_digest))
    }

    pub(crate) fn status_without_reauthorization(
        &self,
        reviewed: &GroupTogglePlan,
    ) -> Result<GroupApplyResult, GroupControlError> {
        self.status_with_expected_decision(reviewed, None)
    }

    fn status_with_expected_decision(
        &self,
        reviewed: &GroupTogglePlan,
        authorization_decision_digest: Option<&str>,
    ) -> Result<GroupApplyResult, GroupControlError> {
        reviewed.verify()?;
        if reviewed.disposition != GroupPlanDisposition::Actionable {
            return Err(GroupControlError::NotActionable);
        }
        let operation_id = reviewed
            .operation_id
            .as_ref()
            .ok_or(GroupControlError::InvalidPlan)?;
        let approval_context = ControlApprovalContext::new(
            self.planner.resolver().context().repository_key(),
            self.planner.resolver().context().workspace_key(),
        )
        .map_err(|error| GroupControlError::ApprovalContext(error.to_string()))?;
        reviewed.approval_expectation_verified(&approval_context)?;
        let app_state_root = self.planner.resolver().context().app_state_root();
        let store = GroupOperationStore::new(
            app_state_root.to_path_buf(),
            self.backup_authentication_key.clone(),
        );
        let existing = store
            .load(operation_id)?
            .ok_or(GroupControlError::OperationUnavailable)?;
        self.existing_result(
            &store,
            existing,
            reviewed,
            &approval_context,
            authorization_decision_digest,
            operation_owner(operation_id)?,
        )
    }

    pub fn operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<GroupOperationRecord>, GroupControlError> {
        GroupOperationStore::new(
            self.planner
                .resolver()
                .context()
                .app_state_root()
                .to_path_buf(),
            self.backup_authentication_key.clone(),
        )
        .load(operation_id)
        .map(|record| record.map(|record| record.value))
        .map_err(Into::into)
    }

    fn existing_result(
        &self,
        store: &GroupOperationStore,
        mut existing: StateSnapshot<GroupOperationRecord>,
        reviewed: &GroupTogglePlan,
        approval_context: &ControlApprovalContext,
        expected_decision_digest: Option<&str>,
        owner: OwnerGeneration,
    ) -> Result<GroupApplyResult, GroupControlError> {
        if existing.value.plan_fingerprint != reviewed.plan_fingerprint
            || existing.value.qualified_name != reviewed.qualified_name
            || existing.value.requested_state != reviewed.target
            || existing.value.repository_key != approval_context.repository_key()
            || existing.value.workspace_key != approval_context.workspace_key()
            || expected_decision_digest
                .is_some_and(|digest| existing.value.authorization_decision_digest != digest)
        {
            return Err(GroupControlError::InvalidPlan);
        }
        if let Some(result) = existing.value.terminal_result.clone() {
            let evidence_available = match self.recover_interrupted_backup_indexes(
                store,
                &existing.value.sealed_plan,
                owner.clone(),
            ) {
                Ok(indexes) => backup_indexes_cover_result(&result, &indexes),
                Err(_) => false,
            };
            return Ok(self.refresh_terminal_observation(reviewed, result, evidence_available));
        }
        if !existing.value.provider_writes_started {
            return Err(GroupControlError::OperationUnavailable);
        }
        let backup_indexes = self.recover_interrupted_backup_indexes(
            store,
            &existing.value.sealed_plan,
            owner.clone(),
        );
        let result = match backup_indexes {
            Ok(backup_indexes) => interrupted_result(&existing.value.sealed_plan, &backup_indexes),
            Err(_) => interrupted_evidence_unverifiable_result(&existing.value.sealed_plan),
        };
        existing.value.terminalize(result.clone())?;
        store.save(&existing.value, &existing.revision, owner)?;
        Ok(result)
    }

    fn apply_cohort(
        &self,
        cohort: &GroupExecutionCohort,
        context: &CohortApplyContext<'_, '_>,
        member_results: &mut [GroupApplyMemberResult],
    ) {
        let mut prepared = Vec::with_capacity(cohort.member_indices.len());
        for member_index in &cohort.member_indices {
            let planned = &context.reviewed.members[*member_index];
            let native_plan = match self.fresh_native_plan(
                &planned.identity,
                context.reviewed.target,
                context.discovery,
                context.selected,
                context.source_views,
                context.journals,
            ) {
                Ok(Some(plan)) => plan,
                Ok(None) => {
                    member_results[*member_index].status = GroupApplyMemberStatus::AlreadyCorrect;
                    member_results[*member_index].reason = None;
                    continue;
                }
                Err(reason) => {
                    mark_cohort_preflight_failed(cohort, member_results, &reason);
                    return;
                }
            };
            let authorization = match self.child_authorization(
                planned,
                cohort,
                &native_plan,
                context.authorization,
                context.parent_expectation,
                context.approval_context,
            ) {
                Ok(authorization) => authorization,
                Err(reason) => {
                    mark_cohort_preflight_failed(cohort, member_results, &reason);
                    return;
                }
            };
            prepared.push((*member_index, native_plan, authorization));
        }

        let mut provider_write_succeeded = false;
        for (member_index, native_plan, authorization) in prepared {
            let result = apply_group_member_toggle(
                self.planner
                    .resolver()
                    .context()
                    .app_state_root()
                    .to_path_buf(),
                &native_plan,
                &authorization,
                context.approval_context,
                self.backup_authentication_key.clone(),
                self.session_authority_key.clone(),
            );
            match result {
                Ok(result) if result.status == ToggleStatus::Applied => {
                    member_results[member_index].backup_id = result.backup_id;
                    if member_results[member_index].backup_id.is_none() {
                        mark_cohort_recovery_required(
                            cohort,
                            member_results,
                            "provider write completed without backup evidence",
                        );
                        return;
                    }
                    member_results[member_index].status = GroupApplyMemberStatus::Changed;
                    member_results[member_index].failure_mode = None;
                    member_results[member_index].reason = None;
                    provider_write_succeeded = true;
                }
                Ok(result) if result.status == ToggleStatus::RecoveryRequired => {
                    let reason = result
                        .reason
                        .unwrap_or_else(|| "recovery-required".to_string());
                    member_results[member_index].status = GroupApplyMemberStatus::Failed;
                    member_results[member_index].failure_mode =
                        Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
                    member_results[member_index].backup_id = result.backup_id;
                    member_results[member_index].reason = Some(reason.clone());
                    mark_cohort_recovery_required(cohort, member_results, &reason);
                    return;
                }
                Ok(result) => {
                    let reason = result
                        .reason
                        .unwrap_or_else(|| "group member apply was blocked".to_string());
                    member_results[member_index].status = GroupApplyMemberStatus::Failed;
                    member_results[member_index].failure_mode = None;
                    member_results[member_index].reason = Some(reason.clone());
                    if provider_write_succeeded {
                        mark_cohort_recovery_required(cohort, member_results, &reason);
                    } else {
                        mark_cohort_preflight_failed(cohort, member_results, &reason);
                    }
                    return;
                }
                Err(error) => {
                    let recovery_required = matches!(
                        error,
                        crate::mutation::NativeToggleControlError::RecoveryRequired(_)
                    );
                    let reason = error.to_string();
                    member_results[member_index].status = GroupApplyMemberStatus::Failed;
                    member_results[member_index].failure_mode = recovery_required
                        .then_some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
                    member_results[member_index].reason = Some(reason.clone());
                    if provider_write_succeeded
                        || member_results[member_index].failure_mode
                            == Some(crate::groups::GroupMemberFailureMode::RecoveryRequired)
                    {
                        mark_cohort_recovery_required(cohort, member_results, &reason);
                    } else {
                        mark_cohort_preflight_failed(cohort, member_results, &reason);
                    }
                    return;
                }
            }
        }
    }

    fn child_authorization(
        &self,
        planned: &crate::groups::GroupMemberPlan,
        cohort: &GroupExecutionCohort,
        native_plan: &crate::mutation::NativeTogglePlan,
        parent: &ControlAuthorization,
        parent_expectation: &ApprovalExpectation,
        context: &ControlApprovalContext,
    ) -> Result<ControlAuthorization, String> {
        let child_expectation = native_plan
            .approval_expectation(context)
            .map_err(|error| error.to_string())?;
        let member_plan_fingerprint = planned
            .item_plan_fingerprint
            .as_deref()
            .ok_or_else(|| "group member plan fingerprint is missing".to_string())?;
        if native_plan.plan_fingerprint != member_plan_fingerprint {
            return Err("group member plan drifted before cohort apply".to_string());
        }
        let child_operation_id = planned
            .child_operation_id
            .as_deref()
            .ok_or_else(|| "group member child operation id is missing".to_string())?;
        if native_plan.transition.operation_id != child_operation_id {
            return Err("group member operation drifted before cohort apply".to_string());
        }
        parent
            .attenuate_for_inventory_group_child(
                parent_expectation,
                &child_expectation,
                &cohort.cohort_id,
                member_plan_fingerprint,
            )
            .map_err(|error| error.to_string())
    }

    fn fresh_native_plan(
        &self,
        identity: &GroupMemberIdentity,
        target: GroupTargetState,
        discovery: &GroupDiscoveryIndex<'_>,
        selected: &BTreeSet<GroupMemberIdentity>,
        source_views: &BTreeMap<String, BTreeSet<GroupMemberIdentity>>,
        journals: &[TransitionJournal],
    ) -> Result<Option<crate::mutation::NativeTogglePlan>, String> {
        let matches = discovery
            .get(identity)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let item = match matches {
            [] => return Err("group member disappeared before cohort apply".to_string()),
            [item] => *item,
            _ => return Err("group member became ambiguous before cohort apply".to_string()),
        };
        if item.enabled == target.enabled() {
            return Ok(None);
        }
        if shared_source_has_unlisted_view(item, selected, source_views) {
            return Err("non-member-fan-out".to_string());
        }
        let context = ControlApprovalContext::new(
            self.planner.resolver().context().repository_key(),
            self.planner.resolver().context().workspace_key(),
        )
        .map_err(|error| error.to_string())?;
        NativeToggleController::new(self.planner.resolver().context().app_state_root())
            .plan_with_journals(item.clone(), &context, journals)
            .map(Some)
            .map_err(|error| error.public_reason_code().to_string())
    }

    fn recover_interrupted_backup_indexes(
        &self,
        store: &GroupOperationStore,
        reviewed: &GroupTogglePlan,
        owner: OwnerGeneration,
    ) -> Result<Vec<GroupCohortBackupIndexV1>, GroupControlError> {
        let mut indexes = store.load_backup_indexes(reviewed)?;
        for index in &indexes {
            for backup_id in &index.backup_ids {
                authenticated_backup_manifest_digest(
                    self.planner.resolver().context().app_state_root(),
                    backup_id,
                    &self.backup_authentication_key,
                )
                .map_err(GroupControlError::BackupEvidence)?;
            }
        }
        let indexed_cohorts = indexes
            .iter()
            .map(|index| index.cohort_id.clone())
            .collect::<BTreeSet<_>>();
        let journals =
            TransitionJournalStore::new(self.planner.resolver().context().app_state_root())
                .list()?;
        let operation_id = reviewed
            .operation_id
            .as_ref()
            .ok_or(GroupControlError::InvalidPlan)?;

        for cohort in &reviewed.cohorts {
            if indexed_cohorts.contains(&cohort.cohort_id) {
                continue;
            }
            let mut member_backup_ids = BTreeMap::new();
            for member_index in &cohort.member_indices {
                let member = &reviewed.members[*member_index];
                if member.outcome != GroupMemberPlanOutcome::Changed {
                    continue;
                }
                let child_operation_id = member
                    .child_operation_id
                    .as_deref()
                    .ok_or(GroupControlError::InvalidPlan)?;
                let Some(journal) = journals
                    .iter()
                    .find(|journal| journal.operation_id == child_operation_id)
                else {
                    continue;
                };
                if journal.operation_kind != TransitionKind::NativeToggle.as_str()
                    || journal.repository_key != self.planner.resolver().context().repository_key()
                    || journal.workspace_key != self.planner.resolver().context().workspace_key()
                {
                    return Err(GroupControlError::InvalidPlan);
                }
                if !has_write_or_backup_evidence(journal.effects.iter().map(|effect| effect.status))
                {
                    continue;
                }
                authenticated_backup_manifest_digest(
                    self.planner.resolver().context().app_state_root(),
                    &journal.backup_id,
                    &self.backup_authentication_key,
                )
                .map_err(GroupControlError::BackupEvidence)?;
                member_backup_ids.insert(*member_index, journal.backup_id.clone());
            }
            let coverage =
                cohort_backup_coverage_from_member_ids(reviewed, cohort, &member_backup_ids);
            if coverage.is_empty() {
                continue;
            }
            let index = GroupCohortBackupIndexV1::new(
                operation_id.clone(),
                cohort.cohort_id.clone(),
                cohort
                    .member_indices
                    .iter()
                    .map(|index| reviewed.members[*index].identity.clone())
                    .collect(),
                cohort.resource_ids.clone(),
                coverage,
                &self.backup_authentication_key,
            )?;
            store.save_backup_index(&index, owner.clone())?;
            indexes.push(index);
        }
        Ok(indexes)
    }

    fn observe_final_state(
        &self,
        reviewed: &GroupTogglePlan,
    ) -> (GroupState, bool, Option<String>) {
        match self.observe_sealed_members(reviewed) {
            Ok(observation) if observation.fresh => {
                let requested = if reviewed.target.enabled() {
                    GroupState::On
                } else {
                    GroupState::Off
                };
                let reason = (observation.state != requested).then(|| {
                    format!(
                        "provider state divergence: requested {requested:?}, observed {:?}",
                        observation.state
                    )
                });
                (observation.state, true, reason)
            }
            Ok(_) => (
                GroupState::Mixed,
                false,
                Some("observation-stale: provider discovery was incomplete".to_string()),
            ),
            Err(error) => (
                GroupState::Mixed,
                false,
                Some(format!("observation-stale: {error}")),
            ),
        }
    }

    fn observe_sealed_members(
        &self,
        reviewed: &GroupTogglePlan,
    ) -> Result<crate::groups::GroupMemberObservation, String> {
        let discovery = match discover_all(self.planner.resolver().context().discovery_roots()) {
            Ok(discovery) => discovery,
            Err(error) => return Err(error.to_string()),
        };
        let identities = reviewed
            .members
            .iter()
            .map(|member| member.identity.clone())
            .collect::<Vec<_>>();
        Ok(self
            .planner
            .resolver()
            .observe_members(&identities, &discovery))
    }

    fn refresh_terminal_observation(
        &self,
        reviewed: &GroupTogglePlan,
        mut result: GroupApplyResult,
        evidence_available: bool,
    ) -> GroupApplyResult {
        if !evidence_available {
            result.lifecycle = GroupOperationLifecycle::RecoveryRequired;
            for member in &mut result.members {
                if member.status == GroupApplyMemberStatus::Changed || member.backup_id.is_some() {
                    member.status = GroupApplyMemberStatus::Failed;
                    member.failure_mode =
                        Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
                    member.reason = Some(
                        "recovery-required: authenticated backup evidence is unavailable"
                            .to_string(),
                    );
                }
            }
            result.final_state = GroupState::Mixed;
            result.observation_fresh = false;
            result.observation_reason =
                Some("observation-stale: authenticated backup evidence is unavailable".to_string());
            return result;
        }
        let (state, fresh, reason) = self.observe_final_state(reviewed);
        result.final_state = state;
        result.observation_fresh = fresh;
        result.observation_reason = reason;
        result
    }
}

fn cohort_backup_coverage(
    reviewed: &GroupTogglePlan,
    cohort: &GroupExecutionCohort,
    member_results: &[GroupApplyMemberResult],
) -> Vec<GroupCohortBackupCoverageV1> {
    let member_backup_ids = cohort
        .member_indices
        .iter()
        .filter_map(|member_index| {
            member_results[*member_index]
                .backup_id
                .clone()
                .map(|backup_id| (*member_index, backup_id))
        })
        .collect::<BTreeMap<_, _>>();
    cohort_backup_coverage_from_member_ids(reviewed, cohort, &member_backup_ids)
}

fn cohort_backup_coverage_from_member_ids(
    reviewed: &GroupTogglePlan,
    cohort: &GroupExecutionCohort,
    member_backup_ids: &BTreeMap<usize, String>,
) -> Vec<GroupCohortBackupCoverageV1> {
    let cohort_members = cohort.member_indices.iter().collect::<BTreeSet<_>>();
    let mut coverage = BTreeMap::<String, (BTreeSet<GroupMemberIdentity>, BTreeSet<String>)>::new();
    for resource_id in &cohort.resource_ids {
        let Some(resource) = reviewed
            .resources
            .iter()
            .find(|resource| resource.resource_id == *resource_id)
        else {
            continue;
        };
        let Some(backup_id) = cohort
            .member_indices
            .iter()
            .filter(|member_index| resource.member_indices.contains(member_index))
            .find_map(|member_index| member_backup_ids.get(member_index))
        else {
            continue;
        };
        let entry = coverage.entry(backup_id.clone()).or_default();
        entry.1.insert(resource_id.clone());
        for member_index in &resource.member_indices {
            if cohort_members.contains(member_index) {
                entry
                    .0
                    .insert(reviewed.members[*member_index].identity.clone());
            }
        }
    }
    coverage
        .into_iter()
        .map(
            |(backup_id, (member_identities, resource_ids))| GroupCohortBackupCoverageV1 {
                backup_id,
                member_identities: member_identities.into_iter().collect(),
                resource_ids: resource_ids.into_iter().collect(),
            },
        )
        .collect()
}

fn normalize_cohort_member_backup_ids(
    reviewed: &GroupTogglePlan,
    cohort: &GroupExecutionCohort,
    coverage: &[GroupCohortBackupCoverageV1],
    member_results: &mut [GroupApplyMemberResult],
) {
    for member_index in &cohort.member_indices {
        let identity = &reviewed.members[*member_index].identity;
        let backup_ids = coverage
            .iter()
            .filter(|item| item.member_identities.contains(identity))
            .map(|item| item.backup_id.clone())
            .collect::<BTreeSet<_>>();
        member_results[*member_index].backup_id = if backup_ids.len() == 1 {
            backup_ids.into_iter().next()
        } else {
            None
        };
    }
}

fn initial_member_results(reviewed: &GroupTogglePlan) -> Vec<GroupApplyMemberResult> {
    reviewed
        .members
        .iter()
        .map(|member| {
            let (status, reason) = match member.outcome {
                GroupMemberPlanOutcome::Changed => (GroupApplyMemberStatus::Failed, None),
                GroupMemberPlanOutcome::AlreadyCorrect => {
                    (GroupApplyMemberStatus::AlreadyCorrect, None)
                }
                GroupMemberPlanOutcome::Blocked => {
                    (GroupApplyMemberStatus::Blocked, member.reason.clone())
                }
                GroupMemberPlanOutcome::Missing => {
                    (GroupApplyMemberStatus::Missing, member.reason.clone())
                }
            };
            let cohort_id = reviewed
                .cohorts
                .iter()
                .find(|cohort| {
                    cohort
                        .member_indices
                        .iter()
                        .any(|index| reviewed.members[*index].identity == member.identity)
                })
                .map(|cohort| cohort.cohort_id.clone());
            GroupApplyMemberResult {
                identity: member.identity.clone(),
                status,
                failure_mode: None,
                reason,
                cohort_id,
                backup_id: None,
            }
        })
        .collect()
}

fn roll_up(members: &[GroupApplyMemberResult]) -> GroupOperationLifecycle {
    if members.iter().any(|member| {
        member.failure_mode == Some(crate::groups::GroupMemberFailureMode::RecoveryRequired)
    }) {
        return GroupOperationLifecycle::RecoveryRequired;
    }
    let succeeded = members
        .iter()
        .any(|member| member.status == GroupApplyMemberStatus::Changed);
    let exceptional = members.iter().any(|member| {
        matches!(
            member.status,
            GroupApplyMemberStatus::Blocked
                | GroupApplyMemberStatus::Missing
                | GroupApplyMemberStatus::Failed
        )
    });
    match (succeeded, exceptional) {
        (true, false) => GroupOperationLifecycle::Completed,
        (true, true) => GroupOperationLifecycle::Partial,
        (false, false) => GroupOperationLifecycle::Completed,
        (false, true) => GroupOperationLifecycle::Failed,
    }
}

fn mark_cohort_recovery_required(
    cohort: &GroupExecutionCohort,
    members: &mut [GroupApplyMemberResult],
    reason: &str,
) {
    for member_index in &cohort.member_indices {
        let member = &mut members[*member_index];
        member.status = GroupApplyMemberStatus::Failed;
        member.failure_mode = Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
        member.reason = Some(format!("recovery-required: {reason}"));
    }
}

fn mark_cohort_preflight_failed(
    cohort: &GroupExecutionCohort,
    members: &mut [GroupApplyMemberResult],
    reason: &str,
) {
    for member_index in &cohort.member_indices {
        let member = &mut members[*member_index];
        if member.status == GroupApplyMemberStatus::AlreadyCorrect {
            continue;
        }
        member.status = GroupApplyMemberStatus::Failed;
        member.failure_mode = None;
        member.reason = Some(format!("cohort-blocked: {reason}"));
    }
}

fn mark_cohort_failed(
    cohort: &GroupExecutionCohort,
    members: &mut [GroupApplyMemberResult],
    reason: &str,
) {
    for member_index in &cohort.member_indices {
        let member = &mut members[*member_index];
        member.status = GroupApplyMemberStatus::Failed;
        member.failure_mode = None;
        member.reason = Some(reason.to_string());
    }
}

fn interrupted_result(
    reviewed: &GroupTogglePlan,
    backup_indexes: &[GroupCohortBackupIndexV1],
) -> GroupApplyResult {
    let aggregate_backup_ids = backup_indexes
        .iter()
        .flat_map(|index| index.backup_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut members = initial_member_results(reviewed);
    for (member_index, planned) in reviewed.members.iter().enumerate() {
        if planned.outcome != GroupMemberPlanOutcome::Changed {
            continue;
        }
        let covered_backup_ids = backup_indexes
            .iter()
            .flat_map(|index| &index.coverage)
            .filter(|coverage| coverage.member_identities.contains(&planned.identity))
            .map(|coverage| coverage.backup_id.clone())
            .collect::<BTreeSet<_>>();
        if covered_backup_ids.len() == 1 {
            apply_interruption_evidence(
                &mut members[member_index],
                planned.outcome,
                covered_backup_ids.into_iter().next(),
            );
        } else {
            let member = &mut members[member_index];
            member.status = GroupApplyMemberStatus::Failed;
            member.failure_mode = Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
            member.reason = Some(if covered_backup_ids.is_empty() {
                "recovery-required: provider writes started but authenticated member backup evidence is unavailable"
                    .to_string()
            } else {
                "recovery-required: multiple authenticated cohort backups cover this member; inspect cohort backup indexes"
                    .to_string()
            });
        }
    }
    let lifecycle = roll_up(&members);
    GroupApplyResult {
        operation_id: reviewed.operation_id.clone().unwrap_or_default(),
        qualified_name: reviewed.qualified_name.clone(),
        plan_fingerprint: reviewed.plan_fingerprint.clone(),
        requested_state: reviewed.target,
        lifecycle,
        members,
        backup_ids: aggregate_backup_ids.into_iter().collect(),
        final_state: GroupState::Mixed,
        observation_fresh: false,
        observation_reason: Some("observation-stale: interrupted group operation".to_string()),
    }
}

fn interrupted_evidence_unverifiable_result(reviewed: &GroupTogglePlan) -> GroupApplyResult {
    let mut result = interrupted_result(reviewed, &[]);
    result.lifecycle = GroupOperationLifecycle::RecoveryRequired;
    for (member, planned) in result.members.iter_mut().zip(&reviewed.members) {
        if planned.outcome == GroupMemberPlanOutcome::Changed {
            member.status = GroupApplyMemberStatus::Failed;
            member.failure_mode = Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
            member.reason = Some("recovery-required: backup evidence is unverifiable".to_string());
        }
    }
    result.observation_reason =
        Some("observation-stale: authenticated backup evidence is unavailable".to_string());
    result
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

fn has_write_or_backup_evidence(
    statuses: impl IntoIterator<Item = EffectCheckpointStatus>,
) -> bool {
    statuses
        .into_iter()
        .any(|status| status != EffectCheckpointStatus::Pending)
}

fn apply_interruption_evidence(
    member: &mut GroupApplyMemberResult,
    planned_outcome: GroupMemberPlanOutcome,
    backup_id: Option<String>,
) {
    if planned_outcome != GroupMemberPlanOutcome::Changed {
        return;
    }
    match backup_id {
        Some(backup_id) => {
            member.status = GroupApplyMemberStatus::Failed;
            member.failure_mode = Some(crate::groups::GroupMemberFailureMode::RecoveryRequired);
            member.reason =
                Some("recovery-required: interrupted group writes are never resumed".to_string());
            member.backup_id = Some(backup_id);
        }
        None => {
            member.status = GroupApplyMemberStatus::Failed;
            member.failure_mode = None;
            member.reason = Some(
                "interrupted-before-write: no authenticated backup evidence was recorded"
                    .to_string(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, ProviderId};

    fn member_result(status: GroupApplyMemberStatus) -> GroupApplyMemberResult {
        GroupApplyMemberResult {
            identity: GroupMemberIdentity::new(
                ProviderId::Codex,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                DiscoveryLayer::Global,
                "codex:global:skill:test",
            )
            .expect("identity"),
            status,
            failure_mode: None,
            reason: Some("original".to_string()),
            cohort_id: None,
            backup_id: None,
        }
    }

    #[test]
    fn all_pending_checkpoints_have_no_backup_or_write_evidence() {
        assert!(!has_write_or_backup_evidence([
            EffectCheckpointStatus::Pending,
            EffectCheckpointStatus::Pending,
        ]));
        assert!(has_write_or_backup_evidence([
            EffectCheckpointStatus::Pending,
            EffectCheckpointStatus::BackedUp,
        ]));
    }

    #[test]
    fn interruption_preserves_non_write_statuses_and_distinguishes_backup_evidence() {
        for (outcome, status) in [
            (
                GroupMemberPlanOutcome::AlreadyCorrect,
                GroupApplyMemberStatus::AlreadyCorrect,
            ),
            (
                GroupMemberPlanOutcome::Blocked,
                GroupApplyMemberStatus::Blocked,
            ),
            (
                GroupMemberPlanOutcome::Missing,
                GroupApplyMemberStatus::Missing,
            ),
        ] {
            let mut member = member_result(status);
            apply_interruption_evidence(&mut member, outcome, None);
            assert_eq!(member.status, status);
            assert_eq!(member.reason.as_deref(), Some("original"));
        }

        let mut before_write = member_result(GroupApplyMemberStatus::Failed);
        apply_interruption_evidence(&mut before_write, GroupMemberPlanOutcome::Changed, None);
        assert_eq!(before_write.status, GroupApplyMemberStatus::Failed);
        assert!(
            before_write
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with("interrupted-before-write:"))
        );

        let mut after_backup = member_result(GroupApplyMemberStatus::Failed);
        apply_interruption_evidence(
            &mut after_backup,
            GroupMemberPlanOutcome::Changed,
            Some("backup-id".to_string()),
        );
        assert_eq!(after_backup.status, GroupApplyMemberStatus::Failed);
        assert_eq!(
            after_backup.failure_mode,
            Some(crate::groups::GroupMemberFailureMode::RecoveryRequired)
        );
        assert_eq!(after_backup.backup_id.as_deref(), Some("backup-id"));
    }

    #[test]
    fn already_correct_members_roll_up_as_completed() {
        assert_eq!(
            roll_up(&[member_result(GroupApplyMemberStatus::AlreadyCorrect)]),
            GroupOperationLifecycle::Completed
        );
    }
}

fn prewrite_drift_result(reviewed: &GroupTogglePlan) -> GroupApplyResult {
    let mut members = initial_member_results(reviewed);
    for member in &mut members {
        if member.status == GroupApplyMemberStatus::Failed {
            member.reason = Some("plan-drift-before-provider-write".to_string());
        }
    }
    GroupApplyResult {
        operation_id: reviewed.operation_id.clone().unwrap_or_default(),
        qualified_name: reviewed.qualified_name.clone(),
        plan_fingerprint: reviewed.plan_fingerprint.clone(),
        requested_state: reviewed.target,
        lifecycle: GroupOperationLifecycle::Failed,
        members,
        backup_ids: Vec::new(),
        final_state: reviewed.definition_view.observed_state(),
        observation_fresh: false,
        observation_reason: Some(
            "observation-stale: plan drift before provider writes".to_string(),
        ),
    }
}

fn operation_matches(
    operation: &GroupOperationRecord,
    reviewed: &GroupTogglePlan,
    approval_context: &ControlApprovalContext,
    decision_digest: &str,
) -> bool {
    operation_scope_matches(operation, reviewed, approval_context)
        && operation.authorization_decision_digest == decision_digest
}

fn operation_scope_matches(
    operation: &GroupOperationRecord,
    reviewed: &GroupTogglePlan,
    approval_context: &ControlApprovalContext,
) -> bool {
    operation.plan_fingerprint == reviewed.plan_fingerprint
        && operation.qualified_name == reviewed.qualified_name
        && operation.requested_state == reviewed.target
        && operation.repository_key == approval_context.repository_key()
        && operation.workspace_key == approval_context.workspace_key()
}

fn operation_owner(operation_id: &str) -> Result<OwnerGeneration, GroupControlError> {
    OwnerGeneration::new(format!("inventory-group-{operation_id}"), 1)
        .map_err(|error| GroupControlError::OperationOwner(error.to_string()))
}

fn acquire_operation_execution_lock(
    app_state_root: &std::path::Path,
    operation_id: &str,
) -> Result<StateResourceLock, GroupControlError> {
    StateResourceLock::acquire_with_timeout(
        app_state_root
            .join("groups")
            .join(format!("group-execution-{operation_id}")),
        Duration::from_secs(2),
    )
    .map_err(Into::into)
}

#[derive(Debug)]
pub enum GroupControlError {
    Plan(GroupPlanError),
    Operation(GroupOperationError),
    Journal(JournalError),
    Approval(crate::approval::ApprovalError),
    State(StateError),
    NotActionable,
    InvalidPlan,
    PlanDrift,
    OperationUnavailable,
    OperationOwner(String),
    ApprovalContext(String),
    BackupEvidence(String),
}

impl From<GroupPlanError> for GroupControlError {
    fn from(error: GroupPlanError) -> Self {
        Self::Plan(error)
    }
}

impl From<GroupOperationError> for GroupControlError {
    fn from(error: GroupOperationError) -> Self {
        Self::Operation(error)
    }
}

impl From<JournalError> for GroupControlError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<crate::approval::ApprovalError> for GroupControlError {
    fn from(error: crate::approval::ApprovalError) -> Self {
        Self::Approval(error)
    }
}

impl From<StateError> for GroupControlError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for GroupControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => error.fmt(formatter),
            Self::Operation(error) => error.fmt(formatter),
            Self::Journal(error) => error.fmt(formatter),
            Self::Approval(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::NotActionable => formatter.write_str("group plan is not actionable"),
            Self::InvalidPlan => formatter.write_str("group plan is invalid"),
            Self::PlanDrift => {
                formatter.write_str("reviewed group plan no longer matches current state")
            }
            Self::OperationUnavailable => {
                formatter.write_str("group operation evidence is unavailable")
            }
            Self::OperationOwner(error) => {
                write!(formatter, "group operation owner is invalid: {error}")
            }
            Self::ApprovalContext(error) => {
                write!(formatter, "group approval context is invalid: {error}")
            }
            Self::BackupEvidence(error) => {
                write!(formatter, "group backup evidence is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for GroupControlError {}
