use unpin_core::{
    control_operation::{
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION, ControlOperationEnvelope,
        ControlOperationLifecycle, ControlResolvedContext,
    },
    provider_reach::{
        ConnectionBoundary, DerivedTargetKind, IncludedTargetOutcome, LifecycleEvidence,
        ProviderCoverageEntry, ProviderReach, ProviderReachError, ProviderReachInput,
        ProviderReachOperationProjection, ProviderReachRequest, ProviderReachTarget,
        SelectedProviderProvenance, classify_lifecycle, filter_derived_targets,
        provider_reach_fingerprint,
    },
    providers::ProviderId,
    transitions::EffectActivation,
};

fn target(provider: ProviderId, id: &str) -> ProviderReachTarget {
    ProviderReachTarget::new(provider, id)
}

#[test]
fn exact_individual_target_establishes_selected_provider() {
    let request = ProviderReachRequest::new(
        ConnectionBoundary::AllProviders,
        ProviderReachInput::Omitted,
        DerivedTargetKind::Individual,
    );
    let preflight = request.validate_before_discovery().expect("preflight");
    let resolved = preflight
        .reconcile_exact_target(Some(ProviderId::Codex))
        .expect("exact target authority");

    assert_eq!(
        resolved.reach(),
        &ProviderReach::selected(
            ProviderId::Codex,
            SelectedProviderProvenance::ExactIndividualTarget,
        )
    );
}

#[test]
fn pinned_boundary_establishes_selected_provider_for_omitted_reach() {
    let request = ProviderReachRequest::new(
        ConnectionBoundary::Pinned(ProviderId::Codex),
        ProviderReachInput::Omitted,
        DerivedTargetKind::Group,
    );
    let resolved = request
        .validate_before_discovery()
        .expect("pinned preflight")
        .reconcile_exact_target(None)
        .expect("pinned authority");

    assert_eq!(
        resolved.reach(),
        &ProviderReach::selected(
            ProviderId::Codex,
            SelectedProviderProvenance::PinnedMcpBoundary,
        )
    );
}

#[test]
fn exact_target_conflict_is_rejected_after_derivation() {
    let request = ProviderReachRequest::new(
        ConnectionBoundary::AllProviders,
        ProviderReachInput::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
        DerivedTargetKind::Individual,
    );
    let error = request
        .validate_before_discovery()
        .expect("preflight")
        .reconcile_exact_target(Some(ProviderId::Zed))
        .expect_err("conflicting target authority");

    assert!(matches!(
        error,
        ProviderReachError::ExactTargetConflict {
            selected: ProviderId::Codex,
            target: ProviderId::Zed,
        }
    ));
}

#[test]
fn reach_filter_preserves_derived_targets_and_reports_exclusions() {
    let reach =
        ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput);
    let filtered = filter_derived_targets(
        &reach,
        vec![
            target(ProviderId::Zed, "zed-item"),
            target(ProviderId::Codex, "codex-item"),
        ],
    );

    assert_eq!(
        filtered.included,
        vec![target(ProviderId::Codex, "codex-item")]
    );
    assert_eq!(filtered.excluded.len(), 1);
    assert_eq!(filtered.excluded[0].provider, ProviderId::Zed);
    assert_eq!(filtered.excluded[0].target_id, "zed-item");
    assert_eq!(
        filtered.excluded[0]
            .reason
            .expect("reach exclusion reason")
            .as_str(),
        "out-of-provider-reach"
    );
}

#[test]
fn all_excluded_targets_have_a_distinct_lifecycle() {
    let evidence = LifecycleEvidence::new(
        Vec::new(),
        vec![ProviderCoverageEntry::excluded(ProviderId::Zed, "zed-item")],
        false,
    );
    assert_eq!(
        classify_lifecycle(&evidence),
        unpin_core::provider_reach::ProviderReachLifecycle::NoTargetsInProviderReach
    );
}

#[test]
fn lifecycle_distinguishes_partial_noop_blocked_and_recovery() {
    let excluded = vec![ProviderCoverageEntry::excluded(ProviderId::Zed, "zed")];
    let partial =
        LifecycleEvidence::new(vec![IncludedTargetOutcome::Applied], excluded.clone(), true);
    assert_eq!(
        classify_lifecycle(&partial),
        unpin_core::provider_reach::ProviderReachLifecycle::Partial
    );

    let no_op = LifecycleEvidence::new(vec![IncludedTargetOutcome::NoOp], Vec::new(), false);
    assert_eq!(
        classify_lifecycle(&no_op),
        unpin_core::provider_reach::ProviderReachLifecycle::NoOp
    );

    let blocked = LifecycleEvidence::new(vec![IncludedTargetOutcome::Blocked], Vec::new(), false);
    assert_eq!(
        classify_lifecycle(&blocked),
        unpin_core::provider_reach::ProviderReachLifecycle::Blocked
    );

    let recovery = LifecycleEvidence::new(vec![IncludedTargetOutcome::Failed], Vec::new(), true);
    assert_eq!(
        classify_lifecycle(&recovery),
        unpin_core::provider_reach::ProviderReachLifecycle::RecoveryRequired
    );
}

#[test]
fn fingerprint_material_is_canonical_and_binds_reach_and_reasons() {
    let first = vec![
        ProviderCoverageEntry::included(ProviderId::Zed, "z"),
        ProviderCoverageEntry::excluded(ProviderId::Codex, "c"),
    ];
    let second = vec![first[1].clone(), first[0].clone()];
    let reach =
        ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput);
    assert_eq!(
        provider_reach_fingerprint(&reach, &first),
        provider_reach_fingerprint(&reach, &second)
    );
    assert_ne!(
        provider_reach_fingerprint(
            &ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::TuiControl,),
            &first,
        ),
        provider_reach_fingerprint(&reach, &first)
    );
}

#[test]
fn reach_aware_projection_uses_schema_v2_without_changing_v1_envelope() {
    let envelope = ControlOperationEnvelope::new(
        "operation-1",
        "native-toggle",
        "fingerprint",
        ControlResolvedContext {
            repository_key: "repo".to_string(),
            workspace_key: "workspace".to_string(),
            session_id: None,
            profile_digest: None,
        },
        ControlOperationLifecycle::Applied,
        EffectActivation::Live,
        None,
        false,
        vec![ProviderId::Codex],
        serde_json::json!({"legacy": true}),
    );
    let projection = ProviderReachOperationProjection::from_envelope(
        &envelope,
        ProviderReach::all(),
        Vec::new(),
    );
    assert_eq!(
        envelope.schema_version,
        CONTROL_OPERATION_ENVELOPE_SCHEMA_VERSION
    );
    assert_eq!(projection.schema_version, 2);
    assert_eq!(projection.operation.schema_version, 1);
    assert_eq!(projection.provider_reach, ProviderReach::all());

    for legacy_lifecycle in [
        ControlOperationLifecycle::Applied,
        ControlOperationLifecycle::NoOp,
    ] {
        let mut legacy_with_exclusions = envelope.clone();
        legacy_with_exclusions.lifecycle = legacy_lifecycle;
        let projection = ProviderReachOperationProjection::from_envelope(
            &legacy_with_exclusions,
            ProviderReach::selected(ProviderId::Codex, SelectedProviderProvenance::ExplicitInput),
            vec![
                ProviderCoverageEntry::included(ProviderId::Codex, "codex-item"),
                ProviderCoverageEntry::excluded(ProviderId::Zed, "zed-item"),
            ],
        );
        assert_eq!(
            projection.lifecycle,
            Some(unpin_core::provider_reach::ProviderReachLifecycle::Partial)
        );
    }
}
