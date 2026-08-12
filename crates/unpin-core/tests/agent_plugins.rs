use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use unpin_core::{
    agent_plugins::{
        AGENT_PLUGIN_SUPPORT, AgentPluginAccess, AgentPluginComponentDisposition,
        AgentPluginComponentKind, AgentPluginState,
    },
    discovery::{
        DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryMutability, DiscoveryRoots,
        DiscoveryWarning, ProviderId, discover_all,
    },
    mutation::{BulkToggleController, BulkTogglePlanError, BulkToggleRequest},
    provider_reach::{
        ConnectionBoundary, IncludedTargetOutcome, ProviderReachInput, SelectedProviderProvenance,
    },
};

const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";

#[test]
fn derives_one_cross_provider_package_from_native_activation_anchors() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");

    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );

    for provider in ["claude", "codex"] {
        let package = fixture
            .path()
            .join(provider)
            .join("global/plugins/cache/acme/connector-kit/1.0.0");
        write(
            &package.join("plugin.json"),
            &format!(
                r#"{{"$schema":"{PLUGIN_SCHEMA}","name":"connector-kit","version":"1.0.0","description":"Portable connector tools"}}"#
            ),
        );
        write(
            &package.join("skills/review/SKILL.md"),
            "---\nname: review\ndescription: Review a change.\n---\nReview the change.\n",
        );
        write(
            &package.join("mcp.json"),
            &format!(
                r#"{{"$schema":"{MCP_SCHEMA}","mcpServers":{{"connector":{{"type":"streamable-http","url":"https://example.test/mcp"}}}}}}"#
            ),
        );
    }

    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let discovery = discover_all(&roots).expect("Agent Plugins discovery succeeds");
    let inventory = discovery.agent_plugins();

    assert_eq!(inventory.len(), 1, "equivalent provider instances merge");
    let package = &inventory[0];
    assert_eq!(package.name, "connector-kit");
    assert_eq!(package.state, AgentPluginState::On);
    assert_eq!(package.access, AgentPluginAccess::Actionable);
    assert_eq!(package.instances.len(), 2);
    assert!(
        package
            .logical_id
            .starts_with("agent-plugin:connector-kit:")
    );

    let providers = package
        .instances
        .iter()
        .map(|instance| instance.provider)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        providers,
        BTreeSet::from([ProviderId::Claude, ProviderId::Codex])
    );

    for instance in &package.instances {
        assert_eq!(instance.state, AgentPluginState::On);
        assert_eq!(instance.access, AgentPluginAccess::Actionable);
        assert_eq!(instance.activations.len(), 1);
        let activation = &instance.activations[0];
        assert_eq!(activation.identity.kind, DiscoveryKind::Plugin);
        assert_eq!(
            activation.identity.category,
            DiscoveryCategory::PluginConfig
        );
        assert!(activation.enabled);

        assert_eq!(instance.components.len(), 2);
        assert!(instance.components.iter().any(|component| {
            component.kind == AgentPluginComponentKind::Skill
                && component.name == "review"
                && component.disposition == AgentPluginComponentDisposition::Available
        }));
        assert!(instance.components.iter().any(|component| {
            component.kind == AgentPluginComponentKind::Mcp
                && component.name == "connector"
                && component.disposition == AgentPluginComponentDisposition::Available
        }));
    }

    let raw_discovery = serde_json::to_value(&discovery).expect("serialize discovery");
    assert_eq!(
        raw_discovery
            .as_object()
            .expect("discovery object")
            .keys()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([&"items".to_string(), &"warnings".to_string()]),
        "internal package provenance must not change DiscoveryOutput JSON",
    );

    let public_inventory = serde_json::to_string(&inventory).expect("serialize package inventory");
    assert!(!public_inventory.contains(&fixture.path().to_string_lossy().into_owned()));
    assert!(!public_inventory.contains("sourcePath"));
    assert!(!public_inventory.contains("statePath"));
}

#[test]
fn package_request_binds_exact_native_activations_context_and_provider_reach() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = false\n",
    );
    for provider in ["claude", "codex"] {
        write_package(
            &fixture
                .path()
                .join(provider)
                .join("global/plugins/cache/acme/connector-kit/1.0.0"),
            "connector-kit",
            &["review"],
        );
    }
    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds");
    let package = discovery.agent_plugins().remove(0);
    let request = BulkToggleRequest::for_agent_plugin(&discovery, &package.logical_id, true)
        .expect("package request")
        .with_reach(
            ConnectionBoundary::All,
            ProviderReachInput::selected(
                ProviderId::Codex,
                SelectedProviderProvenance::ExplicitInput,
            ),
        );

    assert_eq!(request.selector.exact_identities.len(), 2);
    assert!(request.acknowledge_whole_inventory);
    assert_eq!(
        request.selection_context_fingerprint.as_deref(),
        Some(package.projection_fingerprint.as_str())
    );
    let controller = BulkToggleController::new(fixture.path().join("app-state"));
    let mut missing_request = request.clone();
    let mut missing = missing_request.selector.exact_identities[0].clone();
    missing.id = "missing-native-activation".to_string();
    missing_request.selector.exact_identities.push(missing);
    assert!(matches!(
        controller.plan_from_discovery(discovery.clone(), missing_request),
        Err(BulkTogglePlanError::ExactIdentityMissing(_))
    ));
    let plan = controller
        .plan_from_discovery(discovery, request)
        .expect("exact package plan");

    assert_eq!(
        plan.selection_context_fingerprint,
        Some(package.projection_fingerprint)
    );
    assert_eq!(plan.matched.len(), 2);
    assert_eq!(plan.provider_coverage.included().count(), 1);
    assert_eq!(plan.provider_coverage.excluded().count(), 1);
    assert_eq!(plan.included.len(), 1);
    assert_eq!(plan.included[0].item.provider, ProviderId::Codex);
    assert_eq!(plan.included[0].outcome, IncludedTargetOutcome::Applied);
}

#[test]
fn package_request_rejects_manifest_and_native_state_drift_before_writes() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    write_package(&package_root, "connector-kit", &["review"]);
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let discovery = discover_all(&roots).expect("initial package discovery");
    let logical_id = discovery.agent_plugins()[0].logical_id.clone();
    let request = BulkToggleRequest::for_agent_plugin(&discovery, &logical_id, false)
        .expect("package request")
        .with_reach(ConnectionBoundary::All, ProviderReachInput::All);
    let controller = BulkToggleController::new(fixture.path().join("app-state"));
    controller
        .plan_from_discovery(discovery, request.clone())
        .expect("initial package plan");

    write(
        &package_root.join("plugin.json"),
        &format!(r#"{{"$schema":"{PLUGIN_SCHEMA}","name":"connector-kit","version":"1.0.1"}}"#),
    );
    let manifest_error = controller
        .plan_from_discovery(
            discover_all(&roots).expect("manifest drift discovery"),
            request.clone(),
        )
        .expect_err("manifest drift must reject reviewed context");
    assert_eq!(
        manifest_error,
        BulkTogglePlanError::SelectionContextFingerprintMismatch
    );

    write_package(&package_root, "connector-kit", &["review"]);
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = false\n",
    );
    let state_error = controller
        .plan_from_discovery(
            discover_all(&roots).expect("state drift discovery"),
            request,
        )
        .expect_err("convergent state drift must reject reviewed context");
    assert_eq!(
        state_error,
        BulkTogglePlanError::SelectionContextFingerprintMismatch
    );
}

#[test]
fn package_plan_preserves_blocked_and_no_op_activation_dispositions() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":false}}"#,
    );
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    for provider in ["claude", "codex"] {
        write_package(
            &fixture
                .path()
                .join(provider)
                .join("global/plugins/cache/acme/connector-kit/1.0.0"),
            "connector-kit",
            &["review"],
        );
    }
    let mut discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds");
    discovery
        .items
        .iter_mut()
        .find(|item| item.provider == ProviderId::Claude && item.kind == DiscoveryKind::Plugin)
        .expect("Claude activation")
        .mutability = DiscoveryMutability::ReadOnly;
    let package = discovery.agent_plugins().remove(0);
    let request = BulkToggleRequest::for_agent_plugin(&discovery, &package.logical_id, true)
        .expect("package request")
        .with_reach(ConnectionBoundary::All, ProviderReachInput::All)
        .acknowledge_whole_inventory(true);

    let plan = BulkToggleController::new(fixture.path().join("app-state"))
        .plan_from_discovery(discovery, request)
        .expect("partial package plan");

    assert_eq!(plan.blocked.len(), 1);
    assert_eq!(plan.blocked[0].item.provider, ProviderId::Claude);
    assert_eq!(plan.included.len(), 1);
    assert_eq!(plan.included[0].item.provider, ProviderId::Codex);
    assert_eq!(plan.included[0].outcome, IncludedTargetOutcome::NoOp);
    assert_eq!(plan.write_count(), 0);
}

#[test]
fn checked_in_provider_fixture_projects_actionable_claude_and_codex_instances() {
    let roots =
        DiscoveryRoots::fixture_root(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"));
    let first = discover_all(&roots).expect("first fixture discovery");
    let second = discover_all(&roots).expect("second fixture discovery");
    let first = first.agent_plugins();
    let second = second.agent_plugins();

    assert_eq!(first, second, "unchanged scans must be byte-stable");
    let connector = first
        .iter()
        .find(|package| package.name == "connector-kit")
        .expect("fixture connector package");
    assert_eq!(connector.instances.len(), 2);
    assert_eq!(connector.state, AgentPluginState::On);
    assert_eq!(connector.access, AgentPluginAccess::Actionable);
}

#[test]
fn native_identity_not_manifest_display_name_controls_activation_association() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"friendly-name@acme":true}}"#,
    );
    write_package(
        &fixture
            .path()
            .join("claude/global/plugins/cache/acme/different-native-id/1.0.0"),
        "friendly-name",
        &["review"],
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds");
    let package = &discovery.agent_plugins()[0];

    assert_eq!(package.name, "friendly-name");
    assert_eq!(package.state, AgentPluginState::Unknown);
    assert_eq!(package.access, AgentPluginAccess::DiagnosticsOnly);
    assert!(package.instances[0].activations.is_empty());
    assert!(
        package.instances[0]
            .blockers
            .contains(&"native-activation-not-found".to_string())
    );
    assert_eq!(
        BulkToggleRequest::for_agent_plugin(&discovery, &package.logical_id, true),
        Err(BulkTogglePlanError::AgentPluginHasNoActivationAnchors)
    );
}

#[test]
fn diagnostics_only_package_cannot_toggle_a_writable_native_activation() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    write_package(&package_root, "connector-kit", &["review"]);
    write(&package_root.join("mcp.json"), "{");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("invalid package component remains diagnostic");
    let package = &discovery.agent_plugins()[0];

    assert_eq!(package.access, AgentPluginAccess::DiagnosticsOnly);
    assert_eq!(package.instances[0].activations.len(), 1);
    assert_eq!(
        package.instances[0].activations[0].mutability,
        DiscoveryMutability::ReadWrite
    );
    assert_eq!(
        BulkToggleRequest::for_agent_plugin(&discovery, &package.logical_id, false),
        Err(BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors)
    );
}

#[test]
fn diagnostics_only_writable_instance_blocks_package_control() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    for provider in ["claude", "codex"] {
        let package_root = fixture
            .path()
            .join(provider)
            .join("global/plugins/cache/acme/connector-kit/1.0.0");
        write_package(&package_root, "connector-kit", &["review"]);
        let mcp = if provider == "claude" {
            "{".to_string()
        } else {
            serde_json::json!({
                "$schema": MCP_SCHEMA,
                "mcpServers": {
                    "mcp": {
                        "type": "streamable-http",
                        "url": "https://example.test/mcp"
                    }
                }
            })
            .to_string()
        };
        write(&package_root.join("mcp.json"), &mcp);
    }

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("mixed-access package discovery succeeds");
    let package = discovery.agent_plugins().remove(0);
    assert_eq!(package.access, AgentPluginAccess::Actionable);
    assert_eq!(package.instances.len(), 2);
    assert_eq!(
        BulkToggleRequest::for_agent_plugin(&discovery, &package.logical_id, false),
        Err(BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors)
    );
}

#[test]
fn incomplete_inventory_blocks_package_control_before_and_after_review() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    write_package(&package_root, "connector-kit", &["review"]);
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let complete = discover_all(&roots).expect("complete package discovery");
    let logical_id = complete.agent_plugins()[0].logical_id.clone();
    let reviewed_request = BulkToggleRequest::for_agent_plugin(&complete, &logical_id, false)
        .expect("complete inventory creates package request")
        .with_reach(ConnectionBoundary::All, ProviderReachInput::All);

    let mut incomplete = complete;
    incomplete.warnings.push(DiscoveryWarning {
        provider: ProviderId::Codex,
        layer: Some(DiscoveryLayer::Global),
        code: "agent-plugin-cache-incomplete".to_string(),
        message: "fixture intentionally marks the package cache incomplete".to_string(),
    });

    assert_eq!(
        BulkToggleRequest::for_agent_plugin(&incomplete, &logical_id, false),
        Err(BulkTogglePlanError::AgentPluginInventoryIncomplete)
    );
    assert_eq!(
        BulkToggleController::new(fixture.path().join("app-state"))
            .plan_from_discovery(incomplete, reviewed_request),
        Err(BulkTogglePlanError::AgentPluginInventoryIncomplete)
    );
}

#[cfg(unix)]
#[test]
fn symlinked_plugin_cache_entry_marks_inventory_incomplete() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let cache_root = fixture.path().join("codex/global/plugins/cache");
    write_package(
        &cache_root.join("acme/connector-kit/1.0.0"),
        "connector-kit",
        &["review"],
    );
    let outside = fixture.path().join("outside-cache-entry");
    fs::create_dir_all(&outside).expect("outside cache directory");
    std::os::unix::fs::symlink(&outside, cache_root.join("untrusted-link"))
        .expect("untrusted cache symlink");

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("discovery remains available");

    assert!(!discovery.agent_plugin_inventory_complete());
}

#[test]
fn fresh_exact_selection_rejects_new_diagnostics_only_activation_anchor() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    for provider in ["claude", "codex"] {
        let package_root = fixture
            .path()
            .join(provider)
            .join("global/plugins/cache/acme/connector-kit/1.0.0");
        write_package(&package_root, "connector-kit", &["review"]);
    }
    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let reviewed = discover_all(&roots).expect("complete package discovery");
    let logical_id = reviewed.agent_plugins()[0].logical_id.clone();
    let request = BulkToggleRequest::for_agent_plugin(&reviewed, &logical_id, false)
        .expect("complete package request")
        .with_reach(ConnectionBoundary::All, ProviderReachInput::All);

    write(
        &fixture
            .path()
            .join("claude/global/plugins/cache/acme/connector-kit/1.0.0/mcp.json"),
        "{",
    );
    let refreshed = discover_all(&roots).expect("refreshed package discovery");
    assert_eq!(
        BulkToggleController::new(fixture.path().join("app-state"))
            .plan_from_discovery(refreshed, request),
        Err(BulkTogglePlanError::AgentPluginHasDiagnosticsOnlyActivationAnchors)
    );
}

#[test]
fn same_manifest_and_components_from_different_marketplaces_stay_separate() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        concat!(
            "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
            "[plugins.\"connector-kit@contoso\"]\nenabled = false\n",
        ),
    );
    for marketplace in ["acme", "contoso"] {
        write_package(
            &fixture.path().join(format!(
                "codex/global/plugins/cache/{marketplace}/connector-kit/1.0.0"
            )),
            "connector-kit",
            &["review"],
        );
    }

    let inventory = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins();
    assert_eq!(inventory.len(), 2);
    assert!(
        inventory
            .iter()
            .all(|package| package.name == "connector-kit")
    );
    assert_eq!(
        inventory[0].component_signature,
        inventory[1].component_signature
    );
    assert_ne!(inventory[0].logical_id, inventory[1].logical_id);
}

#[test]
fn same_name_with_different_component_sets_stays_separate() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        concat!(
            "[plugins.\"variant-a@acme\"]\nenabled = true\n",
            "[plugins.\"variant-b@acme\"]\nenabled = false\n",
        ),
    );
    write_package(
        &fixture
            .path()
            .join("codex/global/plugins/cache/acme/variant-a/1.0.0"),
        "shared-name",
        &["review"],
    );
    write_package(
        &fixture
            .path()
            .join("codex/global/plugins/cache/acme/variant-b/1.0.0"),
        "shared-name",
        &["deploy"],
    );

    let inventory = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins();

    assert_eq!(inventory.len(), 2);
    assert!(
        inventory
            .iter()
            .all(|package| package.name == "shared-name")
    );
    assert_ne!(
        inventory[0].component_signature,
        inventory[1].component_signature
    );
    assert_eq!(
        inventory
            .iter()
            .map(|package| package.state)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([AgentPluginState::Off, AgentPluginState::On])
    );
}

#[test]
fn source_only_drift_changes_projection_fingerprint_without_changing_logical_identity() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    write_package(&package_root, "connector-kit", &["review"]);
    let roots = DiscoveryRoots::fixture_root(fixture.path());

    let before = discover_all(&roots).unwrap().agent_plugins().remove(0);
    write(
        &package_root.join("skills/review/SKILL.md"),
        "---\nname: review\ndescription: Review a change.\n---\nReview more carefully.\n",
    );
    let after = discover_all(&roots).unwrap().agent_plugins().remove(0);

    assert_eq!(before.logical_id, after.logical_id);
    assert_eq!(before.component_signature, after.component_signature);
    assert_ne!(before.projection_fingerprint, after.projection_fingerprint);
}

#[test]
fn multiple_cached_versions_fail_closed_instead_of_sharing_one_activation() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/project/.claude/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    for version in ["1.0.0", "2.0.0"] {
        write_package(
            &fixture.path().join(format!(
                "claude/global/plugins/cache/acme/connector-kit/{version}"
            )),
            "connector-kit",
            &["review"],
        );
    }

    let inventory = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins();

    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].instances.len(), 2);
    assert_eq!(inventory[0].access, AgentPluginAccess::DiagnosticsOnly);
    assert!(
        inventory[0]
            .instances
            .iter()
            .all(|instance| instance.layer == DiscoveryLayer::Project)
    );
    assert!(inventory[0].instances.iter().all(|instance| {
        instance.activations.is_empty()
            && instance
                .blockers
                .contains(&"multiple-installed-versions".to_string())
    }));
}

#[test]
fn unreadable_plugin_cache_warns_without_aborting_provider_discovery() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    write(
        &fixture.path().join("claude/global/plugins/cache"),
        "not a directory",
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("provider discovery survives an unreadable package cache");

    assert!(discovery.agent_plugins().is_empty());
    assert!(discovery.items.iter().any(|item| {
        item.provider == ProviderId::Claude
            && item.category == DiscoveryCategory::PluginConfig
            && item.display_name == "connector-kit@acme"
    }));
    assert!(discovery.warnings.iter().any(|warning| {
        warning.provider == ProviderId::Claude && warning.code == "agent-plugin-cache-unavailable"
    }));
}

#[test]
fn invalid_manifest_isolated_to_package_and_does_not_synthesize_inventory_rows() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"bad@acme":true}}"#,
    );
    write(
        &fixture
            .path()
            .join("claude/global/plugins/cache/acme/bad/1.0.0/plugin.json"),
        r#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json","name":"Bad Name"}"#,
    );

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("other provider discovery continues");

    assert!(discovery.agent_plugins().is_empty());
    assert!(discovery.items.iter().any(|item| {
        item.provider == ProviderId::Claude
            && item.category == DiscoveryCategory::PluginConfig
            && item.display_name == "bad@acme"
    }));
    let warning = discovery
        .warnings
        .iter()
        .find(|warning| warning.code == "agent-plugin-invalid")
        .expect("bounded package warning");
    assert!(
        !warning
            .message
            .contains(&fixture.path().to_string_lossy().into_owned())
    );
}

#[test]
fn provider_support_matrix_is_explicit_for_every_provider_layer() {
    let actual = AGENT_PLUGIN_SUPPORT
        .iter()
        .map(|row| (row.provider, row.layer))
        .collect::<BTreeSet<_>>();
    let expected = ProviderId::ALL
        .iter()
        .flat_map(|provider| {
            [DiscoveryLayer::Global, DiscoveryLayer::Project]
                .into_iter()
                .map(move |layer| (*provider, layer))
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    assert!(AGENT_PLUGIN_SUPPORT.iter().any(|row| {
        row.provider == ProviderId::Claude
            && row.layer == DiscoveryLayer::Global
            && row.access == AgentPluginAccess::Actionable
    }));
    assert!(AGENT_PLUGIN_SUPPORT.iter().any(|row| {
        row.provider == ProviderId::Cursor
            && row.layer == DiscoveryLayer::Global
            && row.access == AgentPluginAccess::Unsupported
    }));
    let serialized = serde_json::to_value(AGENT_PLUGIN_SUPPORT[0]).expect("serialize support row");
    assert!(serialized.get("rootContract").is_some());
    assert!(serialized.get("root_contract").is_none());
}

#[cfg(unix)]
#[test]
fn escaping_skill_symlink_is_diagnostic_only_and_never_exposes_path() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    write(
        &package_root.join("plugin.json"),
        &format!(r#"{{"$schema":"{PLUGIN_SCHEMA}","name":"connector-kit"}}"#),
    );
    let outside = fixture.path().join("outside-skills");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, package_root.join("skills")).unwrap();

    let package = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins()
        .remove(0);

    assert_eq!(package.access, AgentPluginAccess::DiagnosticsOnly);
    assert!(
        package.instances[0]
            .components
            .iter()
            .any(|component| component.disposition == AgentPluginComponentDisposition::Invalid)
    );
    let serialized = serde_json::to_string(&package).unwrap();
    assert!(!serialized.contains(&fixture.path().to_string_lossy().into_owned()));
}

#[test]
fn advisory_manifest_diagnostics_do_not_disable_a_native_activation() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"connector-kit@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/connector-kit/1.0.0");
    let description = format!("{}\u{1b}[31m", "é".repeat(400));
    let manifest = serde_json::json!({
        "$schema": PLUGIN_SCHEMA,
        "name": "connector-kit",
        "description": description,
        "extensions": "ignored legacy value",
        "futureField": {"enabled": true}
    });
    write(&package_root.join("plugin.json"), &manifest.to_string());
    write(
        &package_root.join("skills/review/SKILL.md"),
        "---\nname: review\ndescription: Review a change.\n---\n",
    );

    let package = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins()
        .remove(0);
    let instance = &package.instances[0];

    assert_eq!(instance.access, AgentPluginAccess::Actionable);
    assert!(instance.blockers.is_empty());
    assert_eq!(
        instance.diagnostics,
        [
            "invalid-extensions-ignored".to_string(),
            "unknown-manifest-fields-ignored".to_string(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    let public = serde_json::to_string(&package).expect("serialize package");
    assert!(!public.contains("\\u001b"));
    assert!(
        instance
            .manifest
            .description
            .as_ref()
            .is_some_and(|value| value.len() <= 512)
    );
}

#[test]
fn oversized_manifest_and_mcp_fail_at_the_narrowest_package_boundary() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"oversized-manifest@acme\"]\nenabled = true\n\
         [plugins.\"oversized-mcp@acme\"]\nenabled = true\n",
    );
    let manifest_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/oversized-manifest/1.0.0");
    write(
        &manifest_root.join("plugin.json"),
        &"x".repeat(1024 * 1024 + 1),
    );
    let mcp_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/oversized-mcp/1.0.0");
    write_package(&mcp_root, "oversized-mcp", &["review"]);
    write(&mcp_root.join("mcp.json"), &"x".repeat(1024 * 1024 + 1));

    let discovery = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("other packages survive bounded input failures");
    let inventory = discovery.agent_plugins();

    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].name, "oversized-mcp");
    assert_eq!(inventory[0].access, AgentPluginAccess::DiagnosticsOnly);
    assert!(
        inventory[0].instances[0]
            .blockers
            .contains(&"mcp-read-error".to_string())
    );
    assert!(
        discovery
            .warnings
            .iter()
            .any(|warning| warning.code == "agent-plugin-invalid")
    );
}

#[test]
fn excessive_json_depth_is_rejected_without_hiding_other_components() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"deep-mcp@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/deep-mcp/1.0.0");
    write_package(&package_root, "deep-mcp", &["review"]);
    let nested = (0..40).fold(
        serde_json::json!(true),
        |value, index| serde_json::json!({format!("level-{index}"): value}),
    );
    write(
        &package_root.join("mcp.json"),
        &serde_json::json!({
            "$schema": MCP_SCHEMA,
            "mcpServers": {"deep": nested}
        })
        .to_string(),
    );

    let package = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins()
        .remove(0);

    assert_eq!(package.access, AgentPluginAccess::DiagnosticsOnly);
    assert!(
        package.instances[0]
            .blockers
            .contains(&"invalid-mcp-document".to_string())
    );
    assert!(package.instances[0].components.iter().any(|component| {
        component.kind == AgentPluginComponentKind::Skill
            && component.disposition == AgentPluginComponentDisposition::Available
    }));
}

#[test]
fn stdio_paths_and_reserved_environment_names_follow_the_standard() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("codex/global/config.toml"),
        "[plugins.\"stdio-checks@acme\"]\nenabled = true\n",
    );
    let package_root = fixture
        .path()
        .join("codex/global/plugins/cache/acme/stdio-checks/1.0.0");
    write_package(&package_root, "stdio-checks", &["review"]);
    write(&package_root.join("bin/server"), "#!/bin/sh\n");
    fs::create_dir_all(package_root.join("data")).expect("stdio cwd");
    write(
        &package_root.join("mcp.json"),
        &serde_json::json!({
            "$schema": MCP_SCHEMA,
            "mcpServers": {
                "bare": {"type": "stdio", "command": "node"},
                "bundled": {"type": "stdio", "command": "./bin/server", "cwd": "./data"},
                "escaping-command": {"type": "stdio", "command": "../outside"},
                "placeholder-command": {"type": "stdio", "command": "${PLUGIN_ROOT}/bin/server"},
                "invalid-cwd": {"type": "stdio", "command": "node", "cwd": "data"},
                "escaping-cwd": {"type": "stdio", "command": "node", "cwd": "${PLUGIN_ROOT}/../outside"},
                "reserved-env": {"type": "stdio", "command": "node", "env": {"PLUGIN_ROOT": "spoofed"}},
                "secure-http": {"type": "streamable-http", "url": "https://example.test/mcp"},
                "loopback-http": {"type": "streamable-http", "url": "http://127.8.9.10:4321/mcp"},
                "lookalike-loopback": {"type": "streamable-http", "url": "http://localhost.evil.test/mcp"}
            }
        })
        .to_string(),
    );

    let package = discover_all(&DiscoveryRoots::fixture_root(fixture.path()))
        .expect("package discovery succeeds")
        .agent_plugins()
        .remove(0);
    let components = &package.instances[0].components;

    for name in ["bare", "bundled", "secure-http", "loopback-http"] {
        assert_eq!(
            components
                .iter()
                .find(|component| component.name == name)
                .map(|component| component.disposition),
            Some(AgentPluginComponentDisposition::Available)
        );
    }
    for name in [
        "escaping-command",
        "placeholder-command",
        "invalid-cwd",
        "escaping-cwd",
        "reserved-env",
        "lookalike-loopback",
    ] {
        assert_eq!(
            components
                .iter()
                .find(|component| component.name == name)
                .map(|component| component.disposition),
            Some(AgentPluginComponentDisposition::Invalid),
            "{name} must fail closed"
        );
    }
    assert_eq!(package.access, AgentPluginAccess::DiagnosticsOnly);
}

#[test]
fn discovery_never_persists_agent_plugin_state() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins fixture");
    write(
        &fixture.path().join("claude/global/settings.json"),
        r#"{"enabledPlugins":{"connector-kit@acme":true}}"#,
    );
    let package_root = fixture
        .path()
        .join("claude/global/plugins/cache/acme/connector-kit/1.0.0");
    write_package(&package_root, "connector-kit", &["review"]);
    let before = snapshot_tree(fixture.path());

    let roots = DiscoveryRoots::fixture_root(fixture.path());
    let first = discover_all(&roots)
        .expect("first package scan")
        .agent_plugins();
    let second = discover_all(&roots)
        .expect("second package scan")
        .agent_plugins();

    assert_eq!(first, second);
    assert_eq!(snapshot_tree(fixture.path()), before);
}

fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).expect("read fixture directory") {
            let entry = entry.expect("fixture entry");
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, files);
            } else if path.is_file() {
                files.insert(
                    path.strip_prefix(root)
                        .expect("relative fixture path")
                        .to_path_buf(),
                    fs::read(path).expect("read fixture file"),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn write_package(root: &Path, manifest_name: &str, skills: &[&str]) {
    write(
        &root.join("plugin.json"),
        &format!(r#"{{"$schema":"{PLUGIN_SCHEMA}","name":"{manifest_name}","version":"1.0.0"}}"#),
    );
    for skill in skills {
        write(
            &root.join("skills").join(skill).join("SKILL.md"),
            &format!(
                "---\nname: {skill}\ndescription: {skill} fixture skill.\n---\nUse {skill}.\n"
            ),
        );
    }
}

fn write(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}
