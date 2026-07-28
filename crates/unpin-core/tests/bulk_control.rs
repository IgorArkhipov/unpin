use unpin_core::{
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput, ProviderId,
    },
    mutation::{
        BulkToggleController, BulkTogglePlanError, BulkTogglePlanStatus, BulkToggleRequest,
        BulkToggleSelector,
    },
    provider_reach::{
        ConnectionBoundary, ProviderReachInput, ProviderReachLifecycle, SelectedProviderProvenance,
    },
};

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
