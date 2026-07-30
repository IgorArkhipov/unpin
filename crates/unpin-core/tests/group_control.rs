mod support;

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceipt, ApprovalReceiptClaims,
    },
    config::{UnpinConfig, UnpinConfigPaths},
    control_operation::{ReachAwareOperationFamily, ReachAwarePrincipal, ReachAwareRootBinding},
    discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryRoots, discover_all},
    groups::{
        GroupAccessContext, GroupApprovalArtifactStore, GroupCohortBackupIndexV1, GroupController,
        GroupDefinitionV1, GroupMemberIdentity, GroupPlanDisposition, GroupPlanMode, GroupPlanner,
        GroupReachAwareApplyContext, GroupRef, GroupResolver, GroupScope, GroupTargetState,
        McpGroupSessionBinding, McpGroupSessionIdentity, McpGroupSessionLeaseStore,
        PersonalGroupStore, RepositoryGroupStore, authenticate_group_approval_challenge,
        issue_group_approval_challenge, verify_group_approval_challenge,
    },
    mutation::{BackupAuthenticationKey, RestoreController, RestoreStatus},
    provider_reach::{ConnectionBoundary, ProviderReach, SelectedProviderProvenance},
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::OwnerGeneration,
    transitions::{TransitionJournalStore, TransitionLifecycle},
};

use support::{control_authorization, control_context};

// Keep synthetic authority windows ahead of the real wall clock now that
// journal attachment validates expiry against trusted system time.
const NOW_UNIX: i64 = 4_000_000_000;

struct GroupHarness {
    _root: TempDir,
    context: GroupAccessContext,
    controller: GroupController,
    backup_key: BackupAuthenticationKey,
    config_path: PathBuf,
    first_skill_path: PathBuf,
}

impl GroupHarness {
    fn new() -> Self {
        let root = TempDir::new().expect("tempdir");
        let fixture_copy = root.path().join("fixtures");
        copy_dir_all(&fixtures_root(), &fixture_copy);
        let workspace = root.path().join("workspace");
        let app_state = root.path().join("state");
        fs::create_dir_all(workspace.join(".git")).expect("workspace");
        fs::create_dir_all(&app_state).expect("state");
        let roots = DiscoveryRoots::fixture_root(&fixture_copy).with_app_state_root(&app_state);
        let config_path = fixture_copy.join("codex/global/config.toml");
        let first_skill_path =
            fixture_copy.join("codex/admin/skills/example-codex-admin-skill/SKILL.md");
        let second_skill_path =
            fixture_copy.join("codex/admin/skills/example-group-control-second/SKILL.md");
        fs::create_dir_all(second_skill_path.parent().expect("second skill parent"))
            .expect("second skill directory");
        fs::write(
            &second_skill_path,
            "---\nname: example-group-control-second\ndescription: Group control fixture skill.\n---\n",
        )
        .expect("second skill");
        let config_source = fs::read_to_string(&config_path).expect("Codex fixture");
        fs::write(
            &config_path,
            format!(
                "{config_source}\n[[skills.config]]\npath = {:?}\nenabled = true\n\n[[skills.config]]\npath = {:?}\nenabled = true\n",
                first_skill_path.to_string_lossy(),
                second_skill_path.to_string_lossy(),
            ),
        )
        .expect("Codex skill override");
        let config = UnpinConfig {
            version: 1,
            app_state_root: app_state,
            cursor_root: root.path().join("cursor"),
            project_root: workspace,
            config_paths: UnpinConfigPaths {
                user_config_path: root.path().join("user.json"),
                project_config_path: root.path().join("project.json"),
            },
        };
        let context =
            GroupAccessContext::from_config(&config, &roots, None, None).expect("group context");
        let discovery = discover_all(&roots).expect("discovery");
        let identities = [
            "codex:global:skill:admin/example-codex-admin-skill",
            "codex:global:skill:admin/example-group-control-second",
        ]
        .iter()
        .map(|id| {
            discovery
                .items
                .iter()
                .find(|item| item.id == *id)
                .map(GroupMemberIdentity::try_from)
                .transpose()
                .expect("identity")
                .unwrap_or_else(|| panic!("Codex skill {id}"))
        })
        .collect();
        let personal = PersonalGroupStore::new(context.clone());
        let repository = RepositoryGroupStore::new(context.clone());
        personal
            .create(
                &GroupDefinitionV1::new("implementation", identities).expect("definition"),
                OwnerGeneration::new("group-control-test", 1).expect("owner"),
            )
            .expect("create");
        let planner = GroupPlanner::new(GroupResolver::new(context.clone(), personal, repository));
        let backup_key = BackupAuthenticationKey::new([0x62; 32]);
        let controller = GroupController::new(
            planner,
            backup_key.clone(),
            SessionAuthorityKey::new([0x53; 32]),
        );
        Self {
            _root: root,
            context,
            controller,
            backup_key,
            config_path,
            first_skill_path,
        }
    }

    fn plan(
        &self,
        target: GroupTargetState,
        mode: GroupPlanMode,
    ) -> unpin_core::groups::GroupTogglePlan {
        self.controller
            .plan(
                &GroupRef::qualified(GroupScope::Personal, "implementation").expect("reference"),
                target,
                10,
                mode,
            )
            .expect("group plan")
    }

    fn controller(&self) -> GroupController {
        GroupController::new(
            GroupPlanner::new(GroupResolver::new(
                self.context.clone(),
                PersonalGroupStore::new(self.context.clone()),
                RepositoryGroupStore::new(self.context.clone()),
            )),
            self.backup_key.clone(),
            SessionAuthorityKey::new([0x53; 32]),
        )
    }

    fn expectation(&self, plan: &unpin_core::groups::GroupTogglePlan) -> ApprovalExpectation {
        plan.approval_expectation(&control_context(
            self.context.repository_key(),
            self.context.workspace_key(),
        ))
        .expect("approval expectation")
    }

    fn reach_context(
        &self,
        authority_key: &SessionAuthorityKey,
        roots: ReachAwareRootBinding,
        boundary: ConnectionBoundary,
        audience: &str,
        issued_at_unix: i64,
        expires_at_unix: i64,
    ) -> GroupReachAwareApplyContext {
        let session_id = "group-reach-session";
        let scope_digest = sha256_hex(
            format!(
                "{}\0{}\0{}",
                self.context.repository_key(),
                self.context.workspace_key(),
                session_id
            )
            .as_bytes(),
        );
        GroupReachAwareApplyContext {
            roots,
            principal: ReachAwarePrincipal::sign(session_id, scope_digest, boundary, authority_key)
                .expect("signed reach-aware principal"),
            audience: audience.to_string(),
            issued_at_unix,
            expires_at_unix,
            now_unix: NOW_UNIX,
        }
    }

    fn codex_roots(&self, app_state_root: &Path) -> ReachAwareRootBinding {
        ReachAwareRootBinding::from_provider_paths(
            app_state_root,
            vec![(
                ProviderId::Codex,
                self.context.discovery_roots().codex_global.clone(),
                "fixture-codex".to_string(),
            )],
            "fixture".to_string(),
        )
        .expect("trusted Codex roots")
    }
}

#[test]
fn actionable_plans_allocate_distinct_high_entropy_operation_ids() {
    let harness = GroupHarness::new();
    let first = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let second = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);

    assert_eq!(first.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(second.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(harness.expectation(&first).profile_digest, None);
    let first_id = first.operation_id.expect("first operation ID");
    let second_id = second.operation_id.expect("second operation ID");
    assert_ne!(first_id, second_id);
    assert!(first_id.starts_with("inventory-group-"));
    assert!(second_id.starts_with("inventory-group-"));
    assert!(first_id.len() >= "inventory-group-".len() + 48);
    assert!(second_id.len() >= "inventory-group-".len() + 48);
}

#[test]
fn beta4_group_plans_without_preserved_members_remain_compatible() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let serialized = serde_json::to_value(&plan).expect("serialize group plan");
    assert!(
        serialized["resources"]
            .as_array()
            .expect("resource plans")
            .iter()
            .all(|resource| resource.get("preservedMembers").is_none())
    );

    let restored: unpin_core::groups::GroupTogglePlan =
        serde_json::from_value(serialized.clone()).expect("deserialize beta.4 plan");
    assert_eq!(
        serde_json::to_value(&restored).expect("serialize restored beta.4 plan"),
        serialized
    );
    restored.verify().expect("verify beta.4 plan");
}

#[test]
fn sealed_plan_structure_binds_scope_name_and_cohort_identity() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);

    let mut wrong_scope = plan.clone();
    wrong_scope.qualified_name = "repository:implementation".to_string();
    assert!(wrong_scope.verify().is_err());

    let mut invalid_cohort = plan;
    invalid_cohort.cohorts[0].cohort_id = "group-cohort-../../escape".to_string();
    assert!(invalid_cohort.verify().is_err());
}

#[test]
fn reach_aware_group_apply_attaches_v2_journal_and_replays_without_writes() {
    let harness = GroupHarness::new();
    let authority_key = SessionAuthorityKey::new([0x53; 32]);
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let durable = harness.reach_context(
        &authority_key,
        harness.codex_roots(harness.context.app_state_root()),
        ConnectionBoundary::All,
        "unpin-core-inventory-group-apply-v1",
        NOW_UNIX,
        NOW_UNIX + 60,
    );
    let authorization = control_authorization(
        harness.context.app_state_root(),
        &expectation,
        "group-reach-aware-first",
        NOW_UNIX,
    );
    let result = harness
        .controller
        .apply_with_reach_aware(&plan, authorization, durable.clone())
        .expect("reach-aware group apply");
    let config_after_apply = fs::read_to_string(&harness.config_path).expect("provider config");
    let backup_count = fs::read_dir(harness.context.app_state_root().join("backups"))
        .expect("backup directory")
        .count();
    let journal_store = TransitionJournalStore::new(harness.context.app_state_root());
    let journal = journal_store
        .list()
        .expect("transition journals")
        .into_iter()
        .find(|journal| journal.operation_id == result.operation_id)
        .expect("group transition journal");
    assert_eq!(journal.lifecycle, TransitionLifecycle::Committed);
    assert_eq!(
        journal.terminal_code.as_deref(),
        Some("provider-reach-applied")
    );
    let envelope = journal.reach_aware.expect("reach-aware envelope");
    assert_eq!(envelope.schema_version, 2);
    assert_eq!(envelope.family, ReachAwareOperationFamily::GroupToggle);
    assert_eq!(envelope.family_schema_version, 2);
    assert_eq!(envelope.operation_id, result.operation_id);
    assert_eq!(envelope.plan_fingerprint, plan.plan_fingerprint);
    assert_eq!(envelope.provider_reach, plan.provider_reach);
    assert_eq!(envelope.provider_coverage, plan.provider_coverage);
    assert_eq!(envelope.roots, durable.roots);
    assert_eq!(envelope.principal, durable.principal);
    assert_eq!(envelope.audience, durable.audience);
    assert_eq!(envelope.prior_state.len(), plan.members.len());
    assert!(
        envelope
            .recovery
            .as_ref()
            .expect("recovery evidence")
            .writes_started
    );
    assert_eq!(
        envelope
            .recovery
            .as_ref()
            .expect("recovery evidence")
            .recovery_reference,
        Some(format!("groups/operations/{}", result.operation_id))
    );
    envelope
        .verify_authenticated(&authority_key)
        .expect("authenticated group envelope");

    let retry = harness
        .controller
        .apply_with_reach_aware(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-reach-aware-retry",
                NOW_UNIX,
            ),
            durable,
        )
        .expect("idempotent reach-aware retry");
    assert_eq!(retry, result);
    assert_eq!(
        fs::read_to_string(&harness.config_path).expect("provider config after retry"),
        config_after_apply
    );
    assert_eq!(
        fs::read_dir(harness.context.app_state_root().join("backups"))
            .expect("backup directory after retry")
            .count(),
        backup_count
    );
}

#[test]
fn reach_aware_group_plan_drift_terminalizes_shared_journal_as_blocked() {
    let harness = GroupHarness::new();
    let authority_key = SessionAuthorityKey::new([0x53; 32]);
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    fs::remove_file(&harness.first_skill_path).expect("introduce reviewed-plan drift");

    let error = harness
        .controller
        .apply_with_reach_aware(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-reach-aware-plan-drift",
                NOW_UNIX,
            ),
            harness.reach_context(
                &authority_key,
                harness.codex_roots(harness.context.app_state_root()),
                ConnectionBoundary::All,
                "unpin-core-inventory-group-apply-v1",
                NOW_UNIX,
                NOW_UNIX + 60,
            ),
        )
        .expect_err("reviewed-plan drift must reject");
    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::PlanDrift
    ));

    let journal = TransitionJournalStore::new(harness.context.app_state_root())
        .list()
        .expect("transition journals")
        .into_iter()
        .find(|journal| journal.operation_id == plan.operation_id.clone().expect("operation id"))
        .expect("group transition journal");
    assert_eq!(journal.lifecycle, TransitionLifecycle::RolledBack);
    assert_eq!(
        journal.terminal_code.as_deref(),
        Some("provider-reach-blocked")
    );
    assert_eq!(
        journal
            .reach_aware
            .as_ref()
            .expect("reach-aware envelope")
            .lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Blocked
    );
}

#[test]
fn reach_aware_group_apply_rejects_controller_root_drift_before_provider_writes() {
    let harness = GroupHarness::new();
    let authority_key = SessionAuthorityKey::new([0x53; 32]);
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let drift_root = TempDir::new().expect("drift state root");
    let durable = harness.reach_context(
        &authority_key,
        harness.codex_roots(drift_root.path()),
        ConnectionBoundary::All,
        "unpin-core-inventory-group-apply-v1",
        NOW_UNIX,
        NOW_UNIX + 60,
    );
    let before = fs::read_to_string(&harness.config_path).expect("provider config before drift");
    let error = harness
        .controller
        .apply_with_reach_aware(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-reach-aware-root-drift",
                NOW_UNIX,
            ),
            durable,
        )
        .expect_err("root drift must be rejected");
    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::ReachAware(_)
    ));
    assert_eq!(
        fs::read_to_string(&harness.config_path).expect("provider config after drift"),
        before
    );
    assert!(
        !harness
            .context
            .app_state_root()
            .join("transactions")
            .exists()
    );
    assert!(!harness.context.app_state_root().join("backups").exists());
    assert!(
        !harness
            .context
            .app_state_root()
            .join("groups")
            .join("operations")
            .exists()
    );
}

#[test]
fn reach_aware_group_apply_rejects_expired_authority_before_provider_writes() {
    let harness = GroupHarness::new();
    let authority_key = SessionAuthorityKey::new([0x53; 32]);
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let mut durable = harness.reach_context(
        &authority_key,
        harness.codex_roots(harness.context.app_state_root()),
        ConnectionBoundary::All,
        "unpin-core-inventory-group-apply-v1",
        NOW_UNIX,
        NOW_UNIX + 60,
    );
    durable.now_unix = durable.expires_at_unix;
    let before = fs::read_to_string(&harness.config_path).expect("provider config before expiry");

    let error = harness
        .controller
        .apply_with_reach_aware(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-reach-aware-expired",
                NOW_UNIX,
            ),
            durable,
        )
        .expect_err("expired reach-aware authority must reject");

    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::ReachAware(_)
    ));
    assert_eq!(
        fs::read_to_string(&harness.config_path).expect("provider config after expiry"),
        before
    );
    assert!(!harness.context.app_state_root().join("backups").exists());
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").expect("write to String");
    }
    encoded
}

#[test]
fn session_leases_renew_expire_and_reject_restart_identity() {
    let root = TempDir::new().expect("tempdir");
    let root = fs::canonicalize(root.path()).expect("canonical tempdir");
    let store = McpGroupSessionLeaseStore::new(&root);
    let key = SessionAuthorityKey::new([0x53; 32]);
    let binding = McpGroupSessionBinding {
        provider: None,
        repository_key: "repository-test".to_string(),
        workspace_key: "workspace-test".to_string(),
    };
    let first = store
        .create(binding.clone(), &key, NOW_UNIX)
        .expect("first lease");
    let initial_expiry = store
        .verify(&first, &key, NOW_UNIX)
        .expect("first lease verifies");
    assert!(initial_expiry > NOW_UNIX);

    store
        .renew(&first, &key, NOW_UNIX + 60)
        .expect("renew lease");
    let renewed_expiry = store
        .verify(&first, &key, initial_expiry)
        .expect("renewed lease remains current");
    assert!(renewed_expiry > initial_expiry);
    assert!(store.verify(&first, &key, renewed_expiry).is_err());

    let replacement = store
        .create(binding, &key, NOW_UNIX + 1)
        .expect("replacement process lease");
    assert_ne!(first.session_id, replacement.session_id);
    assert_ne!(first.generation, replacement.generation);
    let mut forged = first.clone();
    forged.generation = replacement.generation;
    assert!(store.verify(&forged, &key, NOW_UNIX + 1).is_err());
}

#[test]
fn challenges_reject_forgery_oversize_expiry_and_cross_session_replay() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::McpHandoff);
    let store = McpGroupSessionLeaseStore::new(harness.context.app_state_root());
    let key = SessionAuthorityKey::new([0x53; 32]);
    let binding = McpGroupSessionBinding {
        provider: None,
        repository_key: harness.context.repository_key().to_string(),
        workspace_key: harness.context.workspace_key().to_string(),
    };
    let session = store
        .create(binding.clone(), &key, NOW_UNIX)
        .expect("session");
    let lease_expiry = store
        .verify(&session, &key, NOW_UNIX)
        .expect("lease expiry");
    let challenge =
        issue_group_approval_challenge(plan, session.clone(), lease_expiry, &key, NOW_UNIX)
            .expect("challenge");
    verify_group_approval_challenge(&challenge, &session, lease_expiry, &key, NOW_UNIX)
        .expect("challenge verifies");
    authenticate_group_approval_challenge(&challenge, &key).expect("challenge authenticates");

    let mut forged = challenge.clone().into_bytes();
    let last = forged.last_mut().expect("challenge byte");
    *last = if *last == b'a' { b'b' } else { b'a' };
    let forged = String::from_utf8(forged).expect("ASCII challenge");
    assert!(
        verify_group_approval_challenge(&forged, &session, lease_expiry, &key, NOW_UNIX).is_err()
    );
    assert!(authenticate_group_approval_challenge(&"x".repeat(1_100_000), &key).is_err());
    assert!(
        verify_group_approval_challenge(&challenge, &session, lease_expiry, &key, lease_expiry)
            .is_err()
    );

    let replacement = store
        .create(binding, &key, NOW_UNIX + 1)
        .expect("replacement session");
    let replacement_expiry = store
        .verify(&replacement, &key, NOW_UNIX + 1)
        .expect("replacement expiry");
    assert!(
        verify_group_approval_challenge(
            &challenge,
            &replacement,
            replacement_expiry,
            &key,
            NOW_UNIX + 1
        )
        .is_err()
    );
}

#[test]
fn approval_artifacts_are_authenticated_one_use_and_session_bound() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::McpHandoff);
    let expectation = harness.expectation(&plan);
    let app_state_root = harness.context.app_state_root();
    let lease_store = McpGroupSessionLeaseStore::new(app_state_root);
    let session_key = SessionAuthorityKey::new([0x53; 32]);
    let binding = McpGroupSessionBinding {
        provider: None,
        repository_key: harness.context.repository_key().to_string(),
        workspace_key: harness.context.workspace_key().to_string(),
    };
    let session = lease_store
        .create(binding.clone(), &session_key, NOW_UNIX)
        .expect("session");
    let lease_expiry = lease_store
        .verify(&session, &session_key, NOW_UNIX)
        .expect("lease expiry");
    let challenge = issue_group_approval_challenge(
        plan.clone(),
        session.clone(),
        lease_expiry,
        &session_key,
        NOW_UNIX,
    )
    .expect("challenge");
    let receipt = approval_receipt(&expectation, NOW_UNIX);
    let store = GroupApprovalArtifactStore::new(app_state_root);
    let artifact = store
        .issue(
            session.clone(),
            &plan,
            &challenge,
            receipt,
            &session_key,
            NOW_UNIX,
        )
        .expect("artifact");
    let operation_id = plan.operation_id.as_deref().expect("operation ID");
    store
        .load_ready(
            &artifact.artifact_id,
            operation_id,
            &plan.plan_fingerprint,
            &challenge,
            &session,
            &session_key,
            NOW_UNIX,
        )
        .expect("artifact ready");
    store
        .consume(
            &artifact.artifact_id,
            operation_id,
            &plan.plan_fingerprint,
            &challenge,
            &session,
            "decision-digest",
            &session_key,
            NOW_UNIX,
        )
        .expect("artifact consumed");
    assert!(
        store
            .consume(
                &artifact.artifact_id,
                operation_id,
                &plan.plan_fingerprint,
                &challenge,
                &session,
                "decision-digest",
                &session_key,
                NOW_UNIX,
            )
            .is_err()
    );

    let replacement = lease_store
        .create(binding, &session_key, NOW_UNIX + 1)
        .expect("replacement");
    assert!(
        store
            .load_ready(
                &artifact.artifact_id,
                operation_id,
                &plan.plan_fingerprint,
                &challenge,
                &replacement,
                &session_key,
                NOW_UNIX + 1,
            )
            .is_err()
    );
}

#[test]
fn definition_drift_before_sealing_has_zero_provider_writes() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let authorization = control_authorization(
        harness.context.app_state_root(),
        &expectation,
        "group-definition-drift",
        NOW_UNIX,
    );
    let mut extra_member = plan.members[0].identity.clone();
    extra_member.id.push_str("-missing");
    PersonalGroupStore::new(harness.context.clone())
        .replace(
            &GroupDefinitionV1::new(
                "implementation",
                vec![plan.members[0].identity.clone(), extra_member],
            )
            .expect("replacement definition"),
            Some(&plan.group_revision),
            OwnerGeneration::new("group-control-test", 1).expect("owner"),
        )
        .expect("replace group definition");

    let error = harness
        .controller
        .apply(&plan, authorization)
        .expect_err("stale group approval must fail");
    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::PlanDrift
    ));
    assert!(!harness.context.app_state_root().join("backups").exists());
    assert!(
        !harness
            .context
            .app_state_root()
            .join("groups")
            .join("operations")
            .join(format!(
                "{}.json",
                plan.operation_id.as_deref().expect("operation id")
            ))
            .exists()
    );
    let discovery = discover_all(harness.context.discovery_roots()).expect("post-drift discovery");
    assert!(
        discovery
            .items
            .iter()
            .find(|item| item.id == plan.members[0].identity.id)
            .expect("planned member")
            .enabled
    );
}

#[test]
fn shared_resource_members_apply_in_one_cohort_with_one_backup() {
    let harness = GroupHarness::new();
    let before = discover_all(harness.context.discovery_roots()).expect("pre-apply discovery");
    let non_member = before
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:github")
        .expect("non-member MCP")
        .clone();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.members.len(), 2);
    assert_eq!(plan.resources.len(), 1);
    assert_eq!(plan.cohorts.len(), 1);
    assert_eq!(plan.cohorts[0].member_indices.len(), 2);

    let expectation = harness.expectation(&plan);
    let authorization = control_authorization(
        harness.context.app_state_root(),
        &expectation,
        "group-shared-resource",
        NOW_UNIX,
    );
    let result = harness
        .controller
        .apply(&plan, authorization)
        .expect("shared-resource group apply");
    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Completed
    );
    assert_eq!(result.final_state, unpin_core::groups::GroupState::Off);
    assert!(result.observation_fresh);
    assert_eq!(
        result
            .members
            .iter()
            .map(|member| member.identity.clone())
            .collect::<BTreeSet<_>>(),
        plan.members
            .iter()
            .map(|member| member.identity.clone())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        result
            .members
            .iter()
            .filter(|member| {
                member.status == unpin_core::groups::GroupApplyMemberStatus::Changed
            })
            .count(),
        2
    );
    assert_eq!(result.backup_ids.len(), 1);
    let after = discover_all(harness.context.discovery_roots()).expect("post-apply discovery");
    for member in &plan.members {
        assert!(
            !after
                .items
                .iter()
                .find(|item| {
                    GroupMemberIdentity::try_from(*item)
                        .is_ok_and(|identity| identity == member.identity)
                })
                .expect("exact group member")
                .enabled
        );
    }
    let non_member_after = after
        .items
        .iter()
        .find(|item| item.id == non_member.id)
        .expect("non-member after apply");
    assert_eq!(non_member_after.enabled, non_member.enabled);
    assert_eq!(non_member_after.source_path, non_member.source_path);

    let cohort_id = &plan.cohorts[0].cohort_id;
    let cohort_path = harness
        .context
        .app_state_root()
        .join("groups")
        .join("operations")
        .join(&result.operation_id)
        .join("cohorts")
        .join(format!("{cohort_id}.json"));
    let cohort_document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(cohort_path).expect("cohort backup index"))
            .expect("cohort state document");
    assert_eq!(
        cohort_document["value"]["backupIds"]
            .as_array()
            .expect("cohort backup IDs")
            .len(),
        1
    );
    let coverage = cohort_document["value"]["coverage"]
        .as_array()
        .expect("cohort backup coverage");
    assert_eq!(coverage.len(), 1);
    assert_eq!(
        coverage[0]["backupId"],
        cohort_document["value"]["backupIds"][0]
    );
    assert_eq!(
        coverage[0]["memberIdentities"]
            .as_array()
            .expect("covered members")
            .len(),
        2
    );
    assert_eq!(
        coverage[0]["resourceIds"]
            .as_array()
            .expect("covered resources")
            .len(),
        1
    );

    let approval_context = control_context(
        harness.context.repository_key(),
        harness.context.workspace_key(),
    );
    let restore = RestoreController::with_session_authority_key(
        harness.context.app_state_root(),
        SessionAuthorityKey::new([0x53; 32]),
    );
    let restore_plan = restore
        .plan(
            &result.backup_ids[0],
            &approval_context,
            Some(&harness.backup_key),
        )
        .expect("restore plan");
    let restore_expectation = restore_plan
        .approval_expectation(&approval_context)
        .expect("restore expectation");
    let restore_result = restore
        .apply(
            &restore_plan,
            control_authorization(
                harness.context.app_state_root(),
                &restore_expectation,
                "group-shared-resource-restore",
                NOW_UNIX,
            ),
            &approval_context,
            Some(harness.backup_key.clone()),
        )
        .expect("restore group backup");
    assert_eq!(restore_result.status, RestoreStatus::Restored);
    let restored = discover_all(harness.context.discovery_roots()).expect("post-restore discovery");
    for member in &plan.members {
        assert!(
            restored
                .items
                .iter()
                .find(|item| {
                    GroupMemberIdentity::try_from(*item)
                        .is_ok_and(|identity| identity == member.identity)
                })
                .expect("restored exact group member")
                .enabled
        );
    }
    assert_eq!(
        restored
            .items
            .iter()
            .find(|item| item.id == non_member.id)
            .expect("non-member after restore")
            .enabled,
        non_member.enabled
    );
}

#[test]
fn fresh_discovery_rejects_drift_before_group_apply() {
    let harness = GroupHarness::new();
    let discovery = discover_all(harness.context.discovery_roots()).expect("discovery before plan");
    let cursor = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("Cursor MCP identity")
        .expect("Cursor MCP fixture");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(cursor.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand definition");

    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.cohorts.len(), 2);
    fs::remove_file(&harness.first_skill_path).expect("remove planned Codex skill");

    let expectation = harness.expectation(&plan);
    let error = harness
        .controller()
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-cohort-preflight",
                NOW_UNIX,
            ),
        )
        .expect_err("fresh discovery rejects changed group member");

    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::PlanDrift
    ));
    assert!(
        discover_all(harness.context.discovery_roots())
            .expect("discovery after apply")
            .items
            .iter()
            .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
            .expect("Cursor MCP after apply")
            .enabled
    );
}

#[test]
fn best_effort_group_applies_actionable_cohort_with_missing_member() {
    let harness = GroupHarness::new();
    let missing = GroupMemberIdentity::new(
        ProviderId::Codex,
        DiscoveryKind::Skill,
        DiscoveryCategory::Skill,
        DiscoveryLayer::Global,
        "codex:global:skill:missing-from-host",
    )
    .expect("missing member identity");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(missing.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand definition");

    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(
        plan.lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    plan.verify().expect("best-effort plan verifies");
    let missing_plan = plan
        .members
        .iter()
        .find(|member| member.identity == missing)
        .expect("missing member plan");
    assert_eq!(
        missing_plan.outcome,
        unpin_core::groups::GroupMemberPlanOutcome::Missing
    );
    assert_eq!(missing_plan.reason.as_deref(), Some("missing"));
    assert!(missing_plan.affected_resources.is_empty());
    assert!(plan.cohorts.iter().all(|cohort| {
        !cohort
            .member_indices
            .iter()
            .any(|index| plan.members[*index].identity == missing)
    }));

    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-best-effort-missing",
                NOW_UNIX,
            ),
        )
        .expect("best-effort group apply");

    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Partial
    );
    assert_eq!(
        result.provider_reach_lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    assert_eq!(result.final_state, unpin_core::groups::GroupState::Mixed);
    let missing_result = result
        .members
        .iter()
        .find(|member| member.identity == missing)
        .expect("missing member result");
    assert_eq!(
        missing_result.status,
        unpin_core::groups::GroupApplyMemberStatus::Missing
    );
    assert_eq!(missing_result.reason.as_deref(), Some("missing"));
    assert!(missing_result.cohort_id.is_none());
    assert!(missing_result.backup_id.is_none());
    assert_eq!(
        result
            .members
            .iter()
            .filter(|member| {
                member.status == unpin_core::groups::GroupApplyMemberStatus::Changed
            })
            .count(),
        2
    );
}

#[test]
fn shared_resource_protected_member_stays_unchanged_while_safe_cohort_applies() {
    let harness = GroupHarness::new();
    let config = fs::read_to_string(&harness.config_path).expect("Codex config");
    fs::write(
        &harness.config_path,
        format!("{config}\n[mcp_servers.unpin]\ncommand = \"unpin\"\n"),
    )
    .expect("protected MCP fixture");
    let discovery =
        discover_all(harness.context.discovery_roots()).expect("expanded group discovery");
    let protected_item = discovery
        .items
        .iter()
        .find(|item| item.id == "codex:global:configured-mcp:unpin")
        .cloned()
        .expect("protected MCP fixture");
    let protected = GroupMemberIdentity::try_from(&protected_item).expect("protected MCP identity");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(protected.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand definition");

    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(
        plan.lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    let protected_index = plan
        .members
        .iter()
        .position(|member| member.identity == protected)
        .expect("protected member index");
    let protected_plan = &plan.members[protected_index];
    assert_eq!(
        protected_plan.outcome,
        unpin_core::groups::GroupMemberPlanOutcome::Blocked
    );
    assert_eq!(
        protected_plan.reason.as_deref(),
        Some(unpin_core::mutation::CONTROL_PLANE_PROTECTED_REASON)
    );
    assert_eq!(protected_plan.affected_resources.len(), 1);
    assert_eq!(plan.cohorts.len(), 1);
    assert_eq!(plan.cohorts[0].member_indices.len(), 3);
    assert!(plan.cohorts[0].member_indices.contains(&protected_index));
    let protected_resource = plan
        .resources
        .iter()
        .find(|resource| resource.member_indices.contains(&protected_index))
        .expect("protected member resource association");
    assert_eq!(
        protected_plan.affected_resources,
        vec![protected_resource.resource_id.clone()]
    );
    let preservation = protected_resource
        .preserved_members
        .iter()
        .find(|proof| proof.member_index == protected_index)
        .expect("blocked-member preservation proof");
    assert_eq!(
        preservation.source_fingerprint,
        protected_item
            .source_fingerprint
            .clone()
            .expect("protected MCP source fingerprint")
    );
    assert_eq!(preservation.current_enabled, protected_item.enabled);

    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-best-effort-protected-shared-resource",
                NOW_UNIX,
            ),
        )
        .expect("best-effort shared-resource apply");

    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Partial
    );
    assert_eq!(
        result.provider_reach_lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    assert_eq!(result.final_state, unpin_core::groups::GroupState::Mixed);
    let protected_result = result
        .members
        .iter()
        .find(|member| member.identity == protected)
        .expect("protected member result");
    assert_eq!(
        protected_result.status,
        unpin_core::groups::GroupApplyMemberStatus::Blocked
    );
    assert_eq!(
        protected_result.reason.as_deref(),
        Some(unpin_core::mutation::CONTROL_PLANE_PROTECTED_REASON)
    );
    assert_eq!(
        protected_result.cohort_id.as_deref(),
        Some(plan.cohorts[0].cohort_id.as_str())
    );

    let after = discover_all(harness.context.discovery_roots()).expect("post-apply discovery");
    assert!(
        after
            .items
            .iter()
            .find(|item| item.id == protected.id)
            .expect("protected MCP after apply")
            .enabled,
        "the composed Codex config update must preserve the blocked MCP"
    );
    for member in plan
        .members
        .iter()
        .filter(|member| member.outcome == unpin_core::groups::GroupMemberPlanOutcome::Changed)
    {
        assert!(
            !after
                .items
                .iter()
                .find(|item| {
                    GroupMemberIdentity::try_from(*item)
                        .is_ok_and(|identity| identity == member.identity)
                })
                .expect("safe member after apply")
                .enabled
        );
    }
}

#[test]
fn unsafe_shared_resource_blocks_only_its_cohort() {
    let harness = GroupHarness::new();
    let config = fs::read_to_string(&harness.config_path).expect("Codex config");
    fs::write(
        &harness.config_path,
        format!(
            "{config}\n[[skills.config]]\npath = {:?}\nenabled = true\n",
            harness.first_skill_path.to_string_lossy()
        ),
    )
    .expect("ambiguous Codex skill fixture");
    let discovery =
        discover_all(harness.context.discovery_roots()).expect("expanded group discovery");
    let cursor = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("Cursor MCP identity")
        .expect("Cursor MCP fixture");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(cursor.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand definition");

    let codex_before = fs::read_to_string(&harness.config_path).expect("Codex config before plan");
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(
        plan.lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    let ambiguous = plan
        .members
        .iter()
        .find(|member| member.identity.id.contains("example-codex-admin-skill"))
        .expect("ambiguous Codex member");
    assert_eq!(
        ambiguous.outcome,
        unpin_core::groups::GroupMemberPlanOutcome::Blocked
    );
    assert_eq!(ambiguous.reason.as_deref(), Some("native-plan-blocked"));
    let shared = plan
        .members
        .iter()
        .find(|member| member.identity.id.contains("example-group-control-second"))
        .expect("same-resource Codex member");
    assert_eq!(
        shared.outcome,
        unpin_core::groups::GroupMemberPlanOutcome::Blocked
    );
    assert_eq!(shared.reason.as_deref(), Some("native-plan-blocked"));
    let cursor_index = plan
        .members
        .iter()
        .position(|member| member.identity == cursor)
        .expect("Cursor member index");
    assert_eq!(
        plan.members[cursor_index].outcome,
        unpin_core::groups::GroupMemberPlanOutcome::Changed
    );
    assert_eq!(plan.cohorts.len(), 1);
    assert_eq!(plan.cohorts[0].member_indices, vec![cursor_index]);

    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-unsafe-shared-resource",
                NOW_UNIX,
            ),
        )
        .expect("disconnected safe cohort apply");

    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Partial
    );
    assert_eq!(result.final_state, unpin_core::groups::GroupState::Mixed);
    assert_eq!(
        fs::read_to_string(&harness.config_path).expect("Codex config after apply"),
        codex_before,
        "unsafe shared-resource cohort must remain untouched"
    );
    assert_eq!(
        result
            .members
            .iter()
            .find(|member| member.identity == cursor)
            .expect("Cursor result")
            .status,
        unpin_core::groups::GroupApplyMemberStatus::Changed
    );
}

#[test]
fn post_write_backup_index_failure_is_durable_and_retry_never_replays_provider_writes() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let operation_id = plan.operation_id.as_deref().expect("operation ID");
    let operations_root = harness
        .context
        .app_state_root()
        .join("groups")
        .join("operations");
    fs::create_dir_all(&operations_root).expect("operations root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for directory in [
            harness.context.app_state_root().join("groups"),
            operations_root.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private operations directory");
        }
    }
    fs::write(
        operations_root.join(operation_id),
        b"block cohort directory",
    )
    .expect("post-write evidence fault");
    let before = fs::read_to_string(&harness.config_path).expect("provider config before apply");
    let expectation = harness.expectation(&plan);

    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-post-write-evidence-fault",
                NOW_UNIX,
            ),
        )
        .expect("post-write evidence failure is represented as a result");

    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::RecoveryRequired
    );
    let after = fs::read_to_string(&harness.config_path).expect("provider config after apply");
    assert_ne!(
        after, before,
        "the provider write must occur before the fault"
    );
    assert!(after.contains("enabled = false"));
    assert_eq!(result.backup_ids.len(), 1);
    let backup_count = fs::read_dir(harness.context.app_state_root().join("backups"))
        .expect("backup directory")
        .count();
    assert!(backup_count >= 1);

    let operation = harness
        .controller
        .operation(operation_id)
        .expect("load durable operation")
        .expect("durable operation");
    assert_eq!(
        operation.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::RecoveryRequired
    );
    assert_eq!(
        operation
            .terminal_result
            .as_ref()
            .expect("terminal result")
            .lifecycle,
        unpin_core::groups::GroupOperationLifecycle::RecoveryRequired
    );
    RestoreController::with_session_authority_key(
        harness.context.app_state_root(),
        SessionAuthorityKey::new([0x53; 32]),
    )
    .plan(
        &result.backup_ids[0],
        &control_context(
            harness.context.repository_key(),
            harness.context.workspace_key(),
        ),
        Some(&harness.backup_key),
    )
    .expect("authenticated backup remains restorable");

    let retry = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-post-write-evidence-retry",
                NOW_UNIX,
            ),
        )
        .expect("terminal retry returns status");
    assert_eq!(
        retry.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::RecoveryRequired
    );
    assert_eq!(
        fs::read_to_string(&harness.config_path).expect("provider config after retry"),
        after
    );
    assert_eq!(
        fs::read_dir(harness.context.app_state_root().join("backups"))
            .expect("backup directory after retry")
            .count(),
        backup_count,
        "retry must not create another backup or replay provider writes"
    );
}

#[test]
fn backup_index_failure_does_not_skip_disconnected_cohorts() {
    let harness = GroupHarness::new();
    let discovery =
        discover_all(harness.context.discovery_roots()).expect("discovery before definition edit");
    let cursor_identity = discovery
        .items
        .iter()
        .find(|item| item.id == "cursor:global:configured-mcp:modern-global")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("Cursor MCP identity")
        .expect("Cursor MCP fixture");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(cursor_identity.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand definition");

    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    assert_eq!(plan.cohorts.len(), 2);
    let operation_id = plan.operation_id.as_deref().expect("operation ID");
    let operations_root = harness
        .context
        .app_state_root()
        .join("groups")
        .join("operations");
    fs::create_dir_all(&operations_root).expect("operations root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for directory in [
            harness.context.app_state_root().join("groups"),
            operations_root.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private operations directory");
        }
    }
    fs::write(
        operations_root.join(operation_id),
        b"block every cohort index directory",
    )
    .expect("post-write evidence fault");
    let expectation = harness.expectation(&plan);

    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-disconnected-evidence-fault",
                NOW_UNIX,
            ),
        )
        .expect("disconnected cohorts produce a recovery result");

    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::RecoveryRequired
    );
    let after =
        discover_all(harness.context.discovery_roots()).expect("discovery after group apply");
    for identity in plan.members.iter().map(|member| &member.identity) {
        assert!(
            !after
                .items
                .iter()
                .find(|item| {
                    GroupMemberIdentity::try_from(*item)
                        .is_ok_and(|candidate| &candidate == identity)
                })
                .unwrap_or_else(|| panic!("post-apply member {identity:?}"))
                .enabled,
            "every disconnected cohort must still execute"
        );
    }
    let cursor_result = result
        .members
        .iter()
        .find(|member| member.identity == cursor_identity)
        .expect("Cursor result");
    assert_eq!(
        cursor_result.failure_mode,
        Some(unpin_core::groups::GroupMemberFailureMode::RecoveryRequired)
    );
    assert!(cursor_result.backup_id.is_some());
    assert_eq!(result.backup_ids.len(), 2);
}

#[test]
fn provider_plan_drift_before_sealing_has_zero_provider_writes() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let authorization = control_authorization(
        harness.context.app_state_root(),
        &expectation,
        "group-provider-drift",
        NOW_UNIX,
    );
    let original = fs::read_to_string(&harness.config_path).expect("Codex config");
    let enabled_entry = format!(
        "path = {:?}\nenabled = true",
        harness.first_skill_path.to_string_lossy()
    );
    let disabled_entry = format!(
        "path = {:?}\nenabled = false",
        harness.first_skill_path.to_string_lossy()
    );
    assert!(original.contains(&enabled_entry));
    fs::write(
        &harness.config_path,
        original.replacen(&enabled_entry, &disabled_entry, 1),
    )
    .expect("provider drift");

    let error = harness
        .controller
        .apply(&plan, authorization)
        .expect_err("provider drift must reject the reviewed plan");

    assert!(matches!(
        error,
        unpin_core::groups::GroupControlError::PlanDrift
    ));
    assert!(!harness.context.app_state_root().join("backups").exists());
    let discovery = discover_all(harness.context.discovery_roots()).expect("post-drift discovery");
    assert!(
        !discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
            .expect("externally changed member")
            .enabled
    );
    assert!(
        discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:skill:admin/example-group-control-second")
            .expect("untouched member")
            .enabled
    );
}

#[test]
fn concurrent_exact_apply_is_serialized_and_returns_one_terminal_result() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for worker_index in 0..2 {
        let controller = harness.controller.clone();
        let plan = plan.clone();
        let expectation = expectation.clone();
        let app_state_root = harness.context.app_state_root().to_path_buf();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let marker = format!("group-concurrent-exact-{worker_index}");
            let authorization =
                control_authorization(&app_state_root, &expectation, &marker, NOW_UNIX);
            barrier.wait();
            controller.apply(&plan, authorization)
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("apply worker").expect("exact apply"))
        .collect::<Vec<_>>();

    assert_eq!(results[0], results[1]);
    assert_eq!(
        results[0].lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Completed
    );
    assert_eq!(results[0].backup_ids.len(), 1);
    let discovery =
        discover_all(harness.context.discovery_roots()).expect("post-concurrent discovery");
    for member in &plan.members {
        assert!(
            !discovery
                .items
                .iter()
                .find(|item| {
                    GroupMemberIdentity::try_from(*item)
                        .is_ok_and(|identity| identity == member.identity)
                })
                .expect("exact member")
                .enabled
        );
    }
}

#[test]
fn exact_terminal_retry_preserves_lifecycle_and_reports_provider_divergence() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-terminal-retry",
                NOW_UNIX,
            ),
        )
        .expect("initial apply");
    let approval_context = control_context(
        harness.context.repository_key(),
        harness.context.workspace_key(),
    );
    let restore = RestoreController::with_session_authority_key(
        harness.context.app_state_root(),
        SessionAuthorityKey::new([0x53; 32]),
    );
    let restore_plan = restore
        .plan(
            &result.backup_ids[0],
            &approval_context,
            Some(&harness.backup_key),
        )
        .expect("restore plan");
    let restore_expectation = restore_plan
        .approval_expectation(&approval_context)
        .expect("restore expectation");
    restore
        .apply(
            &restore_plan,
            control_authorization(
                harness.context.app_state_root(),
                &restore_expectation,
                "group-terminal-restore",
                NOW_UNIX,
            ),
            &approval_context,
            Some(harness.backup_key.clone()),
        )
        .expect("restore provider state");

    let retry = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-terminal-first",
                NOW_UNIX,
            ),
        )
        .expect("exact terminal retry");

    assert_eq!(
        retry.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Completed
    );
    assert_eq!(retry.final_state, unpin_core::groups::GroupState::On);
    assert!(retry.observation_fresh);
    assert!(
        retry
            .observation_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("provider state divergence"))
    );
}

#[test]
fn terminal_retry_after_definition_edit_observes_sealed_operation_members() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-sealed-members-initial",
                NOW_UNIX,
            ),
        )
        .expect("initial apply");

    let removed_member = plan
        .members
        .iter()
        .find(|member| member.identity.id.contains("example-codex-admin-skill"))
        .expect("member removed by the later definition")
        .identity
        .clone();
    let retained_member = plan
        .members
        .iter()
        .find(|member| member.identity != removed_member)
        .expect("member retained by the later definition")
        .identity
        .clone();
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load current definition")
        .expect("current definition");
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", vec![retained_member])
                .expect("replacement definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("edit definition after terminal apply");

    let disabled_entry = format!(
        "path = {:?}\nenabled = false",
        harness.first_skill_path.to_string_lossy()
    );
    let enabled_entry = format!(
        "path = {:?}\nenabled = true",
        harness.first_skill_path.to_string_lossy()
    );
    let provider_state =
        fs::read_to_string(&harness.config_path).expect("provider state after group apply");
    assert!(provider_state.contains(&disabled_entry));
    fs::write(
        &harness.config_path,
        provider_state.replacen(&disabled_entry, &enabled_entry, 1),
    )
    .expect("diverge removed sealed member");

    let retry = harness
        .controller
        .apply(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-sealed-members-retry",
                NOW_UNIX,
            ),
        )
        .expect("terminal retry");
    let operation = harness
        .controller
        .operation(&result.operation_id)
        .expect("operation evidence")
        .expect("sealed operation");

    assert_eq!(
        retry.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Completed
    );
    assert_eq!(retry.final_state, unpin_core::groups::GroupState::Mixed);
    assert!(
        retry
            .observation_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("provider state divergence"))
    );
    assert_eq!(operation.sealed_plan.members.len(), 2);
    assert!(
        operation
            .sealed_plan
            .members
            .iter()
            .any(|member| member.identity == removed_member)
    );
}

#[test]
fn operation_evidence_rejects_tampering() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Disable, GroupPlanMode::TuiDirect);
    let expectation = harness.expectation(&plan);
    let authorization = control_authorization(
        harness.context.app_state_root(),
        &expectation,
        "group-operation-tamper",
        NOW_UNIX,
    );
    let result = harness
        .controller
        .apply(&plan, authorization)
        .expect("group apply");
    let operation_path = harness
        .context
        .app_state_root()
        .join("groups")
        .join("operations")
        .join(format!("{}.json", result.operation_id));
    let raw = fs::read_to_string(&operation_path).expect("operation record");
    let mut document: serde_json::Value =
        serde_json::from_str(&raw).expect("operation state document");
    document["value"]["requestedState"] = serde_json::json!("enable");
    fs::write(
        &operation_path,
        serde_json::to_vec_pretty(&document).expect("tampered operation state"),
    )
    .expect("tamper operation record");

    assert!(harness.controller.operation(&result.operation_id).is_err());

    let cohort_id = &plan.cohorts.first().expect("execution cohort").cohort_id;
    let cohort_path = harness
        .context
        .app_state_root()
        .join("groups")
        .join("operations")
        .join(&result.operation_id)
        .join("cohorts")
        .join(format!("{cohort_id}.json"));
    let mut cohort_document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cohort_path).expect("cohort backup index"))
            .expect("cohort state document");
    let cohort_index: GroupCohortBackupIndexV1 =
        serde_json::from_value(cohort_document["value"].clone())
            .expect("cohort backup index value");
    cohort_index
        .verify(&harness.backup_key)
        .expect("authenticated cohort backup index");
    cohort_document["value"]["backupIds"][0] = serde_json::json!("tampered-backup-id");
    let tampered_index: GroupCohortBackupIndexV1 =
        serde_json::from_value(cohort_document["value"].clone()).expect("tampered cohort index");
    assert!(tampered_index.verify(&harness.backup_key).is_err());
}

#[test]
fn no_op_plan_creates_no_operation_challenge_or_artifact_state() {
    let harness = GroupHarness::new();
    let plan = harness.plan(GroupTargetState::Enable, GroupPlanMode::McpHandoff);

    assert_eq!(plan.disposition, GroupPlanDisposition::NoOp);
    assert!(plan.operation_id.is_none());
    assert!(
        issue_group_approval_challenge(
            plan,
            McpGroupSessionIdentity {
                session_id: "mcp-group-session-test".to_string(),
                generation: 1,
                binding: McpGroupSessionBinding {
                    provider: None,
                    repository_key: harness.context.repository_key().to_string(),
                    workspace_key: harness.context.workspace_key().to_string(),
                },
            },
            NOW_UNIX + 60,
            &SessionAuthorityKey::new([0x53; 32]),
            NOW_UNIX,
        )
        .is_err()
    );
    assert!(
        !harness
            .context
            .app_state_root()
            .join("groups")
            .join("operations")
            .exists()
    );
    assert!(
        !harness
            .context
            .app_state_root()
            .join("groups")
            .join("approval-artifacts")
            .exists()
    );
}

#[test]
fn selected_reach_noop_with_exclusion_is_partial_without_write_boundary() {
    let harness = GroupHarness::new();
    let discovery = discover_all(harness.context.discovery_roots()).expect("group discovery");
    let excluded = discovery
        .items
        .iter()
        .find(|item| item.id == "zed:global:configured-mcp:github")
        .map(GroupMemberIdentity::try_from)
        .transpose()
        .expect("excluded member identity")
        .expect("Zed fixture member");
    let personal = PersonalGroupStore::new(harness.context.clone());
    let current = personal
        .load("implementation")
        .expect("load group")
        .expect("implementation group");
    let mut members = current.definition.members;
    members.push(excluded.clone());
    personal
        .replace(
            &GroupDefinitionV1::new("implementation", members).expect("expanded definition"),
            Some(&current.revision),
            OwnerGeneration::new("group-control-test", 2).expect("definition owner"),
        )
        .expect("expand group");

    let plan = harness
        .controller
        .plan_with_reach(
            &GroupRef::qualified(GroupScope::Personal, "implementation").expect("reference"),
            GroupTargetState::Enable,
            10,
            GroupPlanMode::TuiDirect,
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
        )
        .expect("selected-provider no-op plan");
    assert_eq!(plan.disposition, GroupPlanDisposition::Actionable);
    assert_eq!(
        plan.lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );
    assert!(plan.cohorts.is_empty());
    assert!(plan.resources.is_empty());
    assert!(
        plan.transition.is_some(),
        "partial handoff needs a transition"
    );
    plan.verify().expect("partial plan verifies");

    let expectation = harness.expectation(&plan);
    let result = harness
        .controller
        .apply_with_reach_aware(
            &plan,
            control_authorization(
                harness.context.app_state_root(),
                &expectation,
                "group-partial-noop",
                NOW_UNIX,
            ),
            harness.reach_context(
                &SessionAuthorityKey::new([0x53; 32]),
                harness.codex_roots(harness.context.app_state_root()),
                ConnectionBoundary::All,
                "unpin-core-inventory-group-apply-v1",
                NOW_UNIX,
                NOW_UNIX + 60,
            ),
        )
        .expect("partial no-op apply");
    assert_eq!(
        result.lifecycle,
        unpin_core::groups::GroupOperationLifecycle::Partial
    );
    assert_eq!(
        result.provider_reach_lifecycle,
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );

    let operation = harness
        .controller
        .operation(&result.operation_id)
        .expect("operation evidence")
        .expect("operation record");
    assert!(!operation.provider_writes_started);
    let journal = TransitionJournalStore::new(harness.context.app_state_root())
        .list()
        .expect("transition journals")
        .into_iter()
        .find(|journal| journal.operation_id == result.operation_id)
        .expect("partial group journal");
    assert_eq!(journal.lifecycle, TransitionLifecycle::Committed);
    assert!(
        !journal
            .reach_aware
            .expect("reach-aware envelope")
            .recovery
            .expect("recovery evidence")
            .writes_started
    );
}

fn approval_receipt(expectation: &ApprovalExpectation, now_unix: i64) -> ApprovalReceipt {
    let key = ApprovalKey::new([0x71; 32]);
    ApprovalIssuer::new(
        key,
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer")
    .issue(ApprovalReceiptClaims {
        version: 1,
        receipt_id: "receipt-group-artifact".to_string(),
        nonce: "nonce-group-artifact".to_string(),
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
    .expect("approval receipt")
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn copy_dir_all(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_dir_all(&entry.path(), &destination_path);
        } else {
            fs::copy(entry.path(), destination_path).expect("copy fixture file");
        }
    }
}
