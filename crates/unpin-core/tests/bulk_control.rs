use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unpin_core::{
    control_operation::{ReachAwarePrincipal, ReachAwareRootBinding},
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput, DiscoveryRoots, ProviderId, discover_all,
    },
    mutation::{
        BULK_TOGGLE_APPROVAL_AUDIENCE, BackupAuthenticationKey, BulkToggleController,
        BulkTogglePlanError, BulkTogglePlanStatus, BulkToggleReachAwareApplyContext,
        BulkToggleRequest, BulkToggleSelector,
    },
    provider_reach::{
        ConnectionBoundary, ProviderReachInput, ProviderReachLifecycle, SelectedProviderProvenance,
    },
    sessions::SessionAuthorityKey,
};

mod support;

use support::{control_authorization, control_context};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn copy_dir_all(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let destination = destination.join(entry.file_name());
        if entry.file_type().expect("fixture entry type").is_dir() {
            copy_dir_all(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy fixture file");
        }
    }
}

fn reach_scope_digest(repository_key: &str, workspace_key: &str, session_id: &str) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in
        Sha256::digest(format!("{repository_key}\0{workspace_key}\0{session_id}").as_bytes())
    {
        write!(&mut encoded, "{byte:02x}").expect("write scope digest");
    }
    encoded
}

struct DurableBulkFixture {
    _fixture_copy: TempDir,
    _app_state: TempDir,
    app_state_root: PathBuf,
    discovery: DiscoveryOutput,
    source_path: PathBuf,
    state_path: PathBuf,
    controller: BulkToggleController,
    plan: unpin_core::mutation::BulkTogglePlan,
    durable: BulkToggleReachAwareApplyContext,
    session_authority_key: SessionAuthorityKey,
}

impl DurableBulkFixture {
    fn new() -> Self {
        let fixture_copy = TempDir::new().expect("temp fixture copy");
        let app_state = TempDir::new().expect("temp app state");
        copy_dir_all(&fixtures_root(), fixture_copy.path());
        let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture_copy.path()))
            .expect("fixture discovery");
        let selected = discovery
            .items
            .iter()
            .find(|item| item.id == "codex:global:skill:admin/example-codex-admin-skill")
            .cloned()
            .expect("Codex fixture skill");
        let source_path = PathBuf::from(&selected.source_path);
        let state_path = PathBuf::from(&selected.state_path);
        let app_state_root = fs::canonicalize(app_state.path()).expect("canonical app-state root");
        let provider_root = fixture_copy.path().join("codex").join("global");
        let roots = ReachAwareRootBinding::from_provider_paths(
            &app_state_root,
            vec![(
                ProviderId::Codex,
                provider_root,
                "fixture-codex".to_string(),
            )],
            "fixture",
        )
        .expect("trusted roots");
        let session_authority_key = SessionAuthorityKey::new([0x53; 32]);
        let controller = BulkToggleController::new(&app_state_root).with_reach_aware_authority(
            BackupAuthenticationKey::new([0x42; 32]),
            session_authority_key.clone(),
            roots.clone(),
        );
        let plan = controller
            .plan_from_discovery(
                discovery.clone(),
                request(
                    BulkToggleSelector {
                        ids: vec![selected.id],
                        ..BulkToggleSelector::default()
                    },
                    false,
                ),
            )
            .expect("bulk fixture plan");
        let approval_context = control_context("bulk-repository", "bulk-workspace");
        let session_id = "bulk-session";
        let principal = ReachAwarePrincipal::sign(
            session_id,
            reach_scope_digest(
                approval_context.repository_key(),
                approval_context.workspace_key(),
                session_id,
            ),
            ConnectionBoundary::All,
            &session_authority_key,
        )
        .expect("signed bulk principal");
        let now_unix = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_secs(),
        )
        .expect("Unix timestamp fits i64");
        let durable = BulkToggleReachAwareApplyContext {
            approval_context,
            roots,
            principal,
            audience: BULK_TOGGLE_APPROVAL_AUDIENCE.to_string(),
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 3_600,
            now_unix,
        };
        Self {
            _fixture_copy: fixture_copy,
            _app_state: app_state,
            app_state_root,
            discovery,
            source_path,
            state_path,
            controller,
            plan,
            durable,
            session_authority_key,
        }
    }

    fn authorization(&self, marker: &str) -> unpin_core::approval::ControlAuthorization {
        let expectation = self
            .plan
            .approval_expectation(
                &self.durable.approval_context,
                &self.durable.principal.session_id,
            )
            .expect("bulk approval expectation");
        control_authorization(&self.app_state_root, &expectation, marker, 150)
    }
}

fn item(provider: ProviderId, id: &str, enabled: bool) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind: DiscoveryKind::Skill,
        category: DiscoveryCategory::Skill,
        layer: DiscoveryLayer::Global,
        id: id.to_string(),
        display_name: id.to_string(),
        enabled,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: format!("/tmp/{provider:?}/{id}/SKILL.md"),
        state_path: format!("/tmp/{provider:?}/config.json"),
        source_fingerprint: None,
        hook: None,
    }
}

fn protected_mcp(provider: ProviderId) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind: DiscoveryKind::Mcp,
        category: DiscoveryCategory::ConfiguredMcp,
        layer: DiscoveryLayer::Global,
        id: format!("{}:global:configured-mcp:unpin", provider.as_str()),
        display_name: "unpin".to_string(),
        enabled: true,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: format!("/tmp/{provider:?}/unpin.json"),
        state_path: format!("/tmp/{provider:?}/config.json"),
        source_fingerprint: None,
        hook: None,
    }
}

fn request(selector: BulkToggleSelector, target_enabled: bool) -> BulkToggleRequest {
    BulkToggleRequest::new(selector, target_enabled).with_reach(
        ConnectionBoundary::All,
        ProviderReachInput::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
    )
}

#[test]
fn bulk_selector_requires_a_non_provider_criterion_before_discovery() {
    let request = BulkToggleRequest::new(BulkToggleSelector::default(), false)
        .with_reach(ConnectionBoundary::All, ProviderReachInput::All);
    let preflight_error = BulkToggleController::validate_before_discovery(&request)
        .expect_err("selector must reject before discovery");
    assert!(matches!(
        preflight_error,
        BulkTogglePlanError::SelectorRequiresNonProviderCriterion
    ));

    let error = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(DiscoveryOutput::default(), request)
        .expect_err("provider-only/empty selector must be rejected");

    assert!(matches!(
        error,
        BulkTogglePlanError::SelectorRequiresNonProviderCriterion
    ));
}

#[test]
fn whole_inventory_acknowledgement_is_required_before_reach_filtering() {
    let discovery = DiscoveryOutput {
        items: vec![
            item(ProviderId::Codex, "codex-a", true),
            item(ProviderId::Codex, "codex-b", true),
            item(ProviderId::Zed, "zed-a", true),
        ],
        warnings: Vec::new(),
    };
    let error = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            discovery,
            request(
                BulkToggleSelector {
                    kinds: vec![DiscoveryKind::Skill],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect_err("whole Codex inventory needs acknowledgement");
    match error {
        BulkTogglePlanError::WholeInventoryAcknowledgementRequired(counts) => {
            assert!(counts.iter().any(|count| {
                count.provider == ProviderId::Codex && count.resolved == 2 && count.total == 2
            }));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn allow_empty_selection_does_not_bypass_all_excluded_reach() {
    let discovery = DiscoveryOutput {
        items: vec![item(ProviderId::Zed, "zed-only", true)],
        warnings: Vec::new(),
    };
    let plan = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            discovery,
            request(
                BulkToggleSelector {
                    ids: vec!["zed-only".to_string()],
                    ..BulkToggleSelector::default()
                },
                false,
            )
            .allow_empty_selection(true),
        )
        .expect("reach exclusion is a valid reviewed plan");
    assert_eq!(plan.status, BulkTogglePlanStatus::NoTargetsInProviderReach);
    assert_eq!(
        plan.lifecycle,
        ProviderReachLifecycle::NoTargetsInProviderReach
    );
    assert!(plan.included.is_empty());
    assert_eq!(plan.provider_coverage.excluded().count(), 1);

    let empty = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![item(ProviderId::Zed, "zed-only", true)],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    ids: vec!["missing".to_string()],
                    ..BulkToggleSelector::default()
                },
                false,
            )
            .allow_empty_selection(true),
        )
        .expect("allowEmptySelection applies to an empty pre-reach match");
    assert_eq!(empty.status, BulkTogglePlanStatus::NoOp);
}

#[test]
fn duplicate_identities_and_unknown_selector_fields_are_rejected() {
    let duplicate = item(ProviderId::Zed, "same", true);
    let error = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![duplicate.clone(), duplicate],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    ids: vec!["same".to_string()],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect_err("duplicate provider-qualified identities must reject");
    assert!(matches!(error, BulkTogglePlanError::DuplicateIdentity(_)));

    let malformed = serde_json::from_value::<BulkToggleSelector>(serde_json::json!({
        "kind": ["skill"]
    }));
    assert!(malformed.is_err(), "selector aliases/unknown fields reject");
}

#[test]
fn equivalent_path_aliases_are_rejected_without_exposing_the_path() {
    let mut first = item(ProviderId::Codex, "first", true);
    first.source_path = "/tmp/shared/skill/SKILL.md".to_string();
    let mut aliased = item(ProviderId::Codex, "aliased", true);
    aliased.source_path = "/tmp/shared/../shared/skill/SKILL.md".to_string();
    let error = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![first, aliased],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    kinds: vec![DiscoveryKind::Skill],
                    ..BulkToggleSelector::default()
                },
                false,
            )
            .acknowledge_whole_inventory(true),
        )
        .expect_err("lexically aliased paths must reject");

    assert!(matches!(
        error,
        BulkTogglePlanError::PathAlias(ref id) if id == "aliased"
    ));
    assert!(
        !error.to_string().contains("/tmp/"),
        "private path is not included in the error"
    );
}

#[test]
fn equivalent_selector_order_has_stable_fingerprint() {
    let first = request(
        BulkToggleSelector {
            ids: vec!["missing-b".to_string(), "missing-a".to_string()],
            ..BulkToggleSelector::default()
        },
        false,
    )
    .allow_empty_selection(true);
    let second = request(
        BulkToggleSelector {
            ids: vec!["missing-a".to_string(), "missing-b".to_string()],
            ..BulkToggleSelector::default()
        },
        false,
    )
    .allow_empty_selection(true);
    let discovery = DiscoveryOutput::default();
    let controller = BulkToggleController::new(std::env::temp_dir());
    let first = controller
        .plan_from_discovery(discovery.clone(), first)
        .expect("first plan");
    let second = controller
        .plan_from_discovery(discovery, second)
        .expect("second plan");
    assert_eq!(first.plan_fingerprint, second.plan_fingerprint);

    let mut tampered = first.clone();
    tampered.allow_empty_selection = false;
    assert!(matches!(
        tampered.verify(),
        Err(BulkTogglePlanError::PlanFingerprintMismatch) | Err(BulkTogglePlanError::InvalidPlan)
    ));
}

#[test]
fn fingerprint_binds_reach_coverage_acknowledgement_and_item_digest() {
    let plan = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![item(ProviderId::Codex, "codex-noop", false)],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    ids: vec!["codex-noop".to_string()],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect("baseline bulk plan");

    let mut tampered_reach = plan.clone();
    tampered_reach.provider_reach = unpin_core::provider_reach::ProviderReach::selected(
        ProviderId::Codex,
        SelectedProviderProvenance::PinnedMcpBoundary,
    );
    assert!(tampered_reach.verify().is_err());

    let mut tampered_coverage = plan.clone();
    tampered_coverage.provider_coverage.entries[0].included = false;
    assert!(tampered_coverage.verify().is_err());

    let mut tampered_acknowledgement = plan.clone();
    tampered_acknowledgement.acknowledgement.acknowledged = true;
    assert!(tampered_acknowledgement.verify().is_err());

    let mut tampered_item_digest = plan;
    tampered_item_digest.included[0].operation_digest = "sha256:tampered".to_string();
    assert!(tampered_item_digest.verify().is_err());
}

#[test]
fn no_op_included_item_plus_reach_exclusion_is_partial() {
    let plan = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![
                    item(ProviderId::Codex, "codex-noop", false),
                    item(ProviderId::Zed, "zed-excluded", true),
                ],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    kinds: vec![DiscoveryKind::Skill],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect("included no-op plus reach exclusion plans");
    assert_eq!(plan.lifecycle, ProviderReachLifecycle::Partial);
    assert_eq!(plan.status, BulkTogglePlanStatus::Planned);
    assert_eq!(plan.included.len(), 1);
    assert!(plan.blocked.is_empty(), "no-op is not a blocker");
}

#[test]
fn in_reach_blocker_blocks_the_whole_plan_even_with_an_included_no_op() {
    let no_op = item(ProviderId::Codex, "codex-noop", false);
    let protected = protected_mcp(ProviderId::Codex);
    let plan = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![no_op.clone(), protected.clone()],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    ids: vec![no_op.id, protected.id],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect("blocker is represented by a non-approvable plan");

    assert_eq!(plan.lifecycle, ProviderReachLifecycle::Blocked);
    assert_eq!(plan.status, BulkTogglePlanStatus::Blocked);
    assert_eq!(
        plan.included.len(),
        1,
        "the no-op remains included coverage"
    );
    assert_eq!(plan.blocked.len(), 1);
}

#[test]
fn operation_id_is_bound_to_the_reviewed_bulk_fingerprint() {
    let plan = BulkToggleController::new(std::env::temp_dir())
        .plan_from_discovery(
            DiscoveryOutput {
                items: vec![item(ProviderId::Codex, "codex-noop", false)],
                warnings: Vec::new(),
            },
            request(
                BulkToggleSelector {
                    ids: vec!["codex-noop".to_string()],
                    ..BulkToggleSelector::default()
                },
                false,
            ),
        )
        .expect("baseline bulk plan");
    let mut tampered = plan;
    tampered.operation_id.push_str("-tampered");
    assert!(matches!(
        tampered.verify(),
        Err(BulkTogglePlanError::PlanFingerprintMismatch)
    ));
}

#[test]
fn durable_bulk_handoff_survives_restart_and_terminal_replay_is_idempotent() {
    let fixture = DurableBulkFixture::new();
    let handoff = fixture
        .controller
        .seal_handoff(&fixture.plan, &fixture.durable)
        .expect("seal durable bulk handoff");
    assert_eq!(handoff.operation_id, fixture.plan.operation_id);
    assert_eq!(handoff.plan_fingerprint, fixture.plan.plan_fingerprint);

    let restarted = BulkToggleController::new(&fixture.app_state_root);
    let loaded = restarted
        .load_handoff(&handoff.operation_id)
        .expect("load handoff after restart");
    assert_eq!(loaded, fixture.plan);
    assert!(
        fixture.source_path.exists(),
        "sealing the handoff must not write provider state"
    );

    let mut resumed_durable = fixture.durable.clone();
    resumed_durable.issued_at_unix += 1;
    resumed_durable.expires_at_unix += 1;
    let applied = fixture
        .controller
        .apply_with_reach_aware(
            &fixture.plan,
            fixture.authorization("bulk-first-apply"),
            resumed_durable,
            fixture.discovery.clone(),
        )
        .expect("apply reviewed bulk operation");
    assert_eq!(applied.lifecycle, ProviderReachLifecycle::Applied);
    assert!(fixture.source_path.exists(), "Codex keeps the skill source");
    assert!(
        fs::read_to_string(&fixture.state_path)
            .expect("rewritten Codex config")
            .contains("enabled = false"),
        "the reviewed fixture skill is disabled in native provider state"
    );
    let backups_before_replay = fs::read_dir(fixture.app_state_root.join("backups"))
        .expect("bulk backup directory")
        .count();

    let replay = fixture
        .controller
        .apply_with_reach_aware(
            &fixture.plan,
            fixture.authorization("bulk-terminal-replay"),
            fixture.durable.clone(),
            fixture.discovery.clone(),
        )
        .expect("terminal replay returns sealed result");
    assert_eq!(replay, applied);
    assert_eq!(
        fs::read_dir(fixture.app_state_root.join("backups"))
            .expect("bulk backup directory after replay")
            .count(),
        backups_before_replay,
        "terminal replay must not perform another provider write"
    );

    let mut expired_replay_context = fixture.durable.clone();
    expired_replay_context.now_unix = expired_replay_context.expires_at_unix;
    let expired_replay = fixture
        .controller
        .apply_with_reach_aware(
            &fixture.plan,
            fixture.authorization("bulk-expired-terminal-replay"),
            expired_replay_context,
            fixture.discovery,
        )
        .expect("expired terminal replay returns cached result");
    assert_eq!(expired_replay, applied);
    assert_eq!(
        fs::read_dir(fixture.app_state_root.join("backups"))
            .expect("bulk backup directory after expired replay")
            .count(),
        backups_before_replay,
        "expired terminal replay must not perform another provider write"
    );
}

#[test]
fn durable_bulk_drift_and_expiry_reject_before_provider_writes() {
    let drifted = DurableBulkFixture::new();
    let mut fresh = drifted.discovery.clone();
    fresh
        .items
        .iter_mut()
        .find(|item| item.id == drifted.plan.matched[0].id)
        .expect("drifted item")
        .enabled = false;
    let result = drifted
        .controller
        .apply_with_reach_aware(
            &drifted.plan,
            drifted.authorization("bulk-drift"),
            drifted.durable,
            fresh,
        )
        .expect("pre-write drift becomes a durable blocked result");
    assert_eq!(result.lifecycle, ProviderReachLifecycle::Blocked);
    assert!(
        drifted.source_path.exists(),
        "drift must block before the fixture provider is changed"
    );
    assert!(!drifted.app_state_root.join("backups").exists());

    let expired = DurableBulkFixture::new();
    let mut expired_context = expired.durable.clone();
    expired_context.now_unix = expired_context.expires_at_unix;
    let error = expired
        .controller
        .apply_with_reach_aware(
            &expired.plan,
            expired.authorization("bulk-expired"),
            expired_context,
            expired.discovery,
        )
        .expect_err("expired durable authority must reject");
    assert!(matches!(error, BulkTogglePlanError::ReachAware(_)));
    assert!(
        expired.source_path.exists(),
        "expiry must reject before provider writes"
    );
    assert!(!expired.app_state_root.join("backups").exists());
}

#[test]
fn durable_bulk_rejects_scope_audience_and_root_mismatches_before_writes() {
    let wrong_scope = DurableBulkFixture::new();
    let mut scope_context = wrong_scope.durable.clone();
    scope_context.principal = ReachAwarePrincipal::sign(
        scope_context.principal.session_id.clone(),
        "0".repeat(64),
        ConnectionBoundary::All,
        &wrong_scope.session_authority_key,
    )
    .expect("signed wrong-scope principal");
    let scope_error = wrong_scope
        .controller
        .apply_with_reach_aware(
            &wrong_scope.plan,
            wrong_scope.authorization("bulk-wrong-scope"),
            scope_context,
            wrong_scope.discovery,
        )
        .expect_err("authenticated scope mismatch must reject");
    assert!(matches!(scope_error, BulkTogglePlanError::ReachAware(_)));
    assert!(wrong_scope.source_path.exists());
    assert!(!wrong_scope.app_state_root.join("backups").exists());

    let wrong_audience = DurableBulkFixture::new();
    let mut audience_context = wrong_audience.durable.clone();
    audience_context.audience = "wrong-bulk-audience".to_string();
    let audience_error = wrong_audience
        .controller
        .apply_with_reach_aware(
            &wrong_audience.plan,
            wrong_audience.authorization("bulk-wrong-audience"),
            audience_context,
            wrong_audience.discovery,
        )
        .expect_err("audience mismatch must reject");
    assert!(matches!(audience_error, BulkTogglePlanError::ReachAware(_)));
    assert!(wrong_audience.source_path.exists());
    assert!(!wrong_audience.app_state_root.join("backups").exists());

    let wrong_root = DurableBulkFixture::new();
    let drift_root = TempDir::new().expect("drift app-state root");
    let mut root_context = wrong_root.durable.clone();
    root_context.roots = ReachAwareRootBinding::from_provider_paths(
        drift_root.path(),
        vec![(
            ProviderId::Codex,
            PathBuf::from(&root_context.roots.provider_roots[0].root),
            "fixture-codex".to_string(),
        )],
        "fixture",
    )
    .expect("mismatched trusted roots");
    let root_error = wrong_root
        .controller
        .apply_with_reach_aware(
            &wrong_root.plan,
            wrong_root.authorization("bulk-wrong-root"),
            root_context,
            wrong_root.discovery,
        )
        .expect_err("trusted-root mismatch must reject");
    assert!(matches!(root_error, BulkTogglePlanError::ReachAware(_)));
    assert!(wrong_root.source_path.exists());
    assert!(!wrong_root.app_state_root.join("backups").exists());
}

#[test]
fn durable_bulk_payload_and_journal_tampering_fail_closed() {
    let payload_tamper = DurableBulkFixture::new();
    payload_tamper
        .controller
        .seal_handoff(&payload_tamper.plan, &payload_tamper.durable)
        .expect("seal payload-tamper handoff");
    let payload_path = payload_tamper
        .app_state_root
        .join("transactions")
        .join("payloads")
        .join("bulk-toggle")
        .join(format!("{}.json", payload_tamper.plan.operation_id));
    let mut payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&payload_path).expect("bulk family payload"))
            .expect("bulk payload document");
    payload["value"]["plan"]["targetEnabled"] = serde_json::json!(true);
    fs::write(
        &payload_path,
        serde_json::to_vec_pretty(&payload).expect("tampered payload document"),
    )
    .expect("tamper family payload");
    assert!(
        payload_tamper
            .controller
            .apply_with_reach_aware(
                &payload_tamper.plan,
                payload_tamper.authorization("bulk-payload-tamper"),
                payload_tamper.durable,
                payload_tamper.discovery,
            )
            .is_err()
    );
    assert!(payload_tamper.source_path.exists());
    assert!(!payload_tamper.app_state_root.join("backups").exists());

    let journal_tamper = DurableBulkFixture::new();
    journal_tamper
        .controller
        .seal_handoff(&journal_tamper.plan, &journal_tamper.durable)
        .expect("seal journal-tamper handoff");
    let journal_path = journal_tamper
        .app_state_root
        .join("transactions")
        .join(format!("{}.json", journal_tamper.plan.operation_id));
    let mut journal: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&journal_path).expect("bulk transition journal"))
            .expect("bulk journal document");
    journal["value"]["reachAware"]["planFingerprint"] = serde_json::json!("sha256:tampered");
    fs::write(
        &journal_path,
        serde_json::to_vec_pretty(&journal).expect("tampered journal document"),
    )
    .expect("tamper transition journal");
    assert!(
        journal_tamper
            .controller
            .apply_with_reach_aware(
                &journal_tamper.plan,
                journal_tamper.authorization("bulk-journal-tamper"),
                journal_tamper.durable,
                journal_tamper.discovery,
            )
            .is_err()
    );
    assert!(journal_tamper.source_path.exists());
    assert!(!journal_tamper.app_state_root.join("backups").exists());
}

#[test]
fn concurrent_durable_bulk_apply_elects_one_writer() {
    let fixture = DurableBulkFixture::new();
    let first_authorization = fixture.authorization("bulk-concurrent-first");
    let second_authorization = fixture.authorization("bulk-concurrent-second");
    let barrier = Arc::new(Barrier::new(3));

    let first_controller = fixture.controller.clone();
    let first_plan = fixture.plan.clone();
    let first_durable = fixture.durable.clone();
    let first_discovery = fixture.discovery.clone();
    let first_barrier = barrier.clone();
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_controller.apply_with_reach_aware(
            &first_plan,
            first_authorization,
            first_durable,
            first_discovery,
        )
    });

    let second_controller = fixture.controller.clone();
    let second_plan = fixture.plan.clone();
    let second_durable = fixture.durable.clone();
    let second_discovery = fixture.discovery.clone();
    let second_barrier = barrier.clone();
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_controller.apply_with_reach_aware(
            &second_plan,
            second_authorization,
            second_durable,
            second_discovery,
        )
    });

    barrier.wait();
    let first_result = first
        .join()
        .expect("first apply thread")
        .expect("first apply");
    let second_result = second
        .join()
        .expect("second apply thread")
        .expect("second apply");
    assert_eq!(first_result, second_result);
    assert_eq!(first_result.lifecycle, ProviderReachLifecycle::Applied);
    assert_eq!(
        fs::read_dir(fixture.app_state_root.join("backups"))
            .expect("concurrent backup directory")
            .count(),
        1,
        "the family lock permits exactly one provider write sequence"
    );
}
