use std::{collections::BTreeSet, path::Path};

use unpin_core::{
    capabilities::{CAPABILITY_ROWS, load_capability_matrix},
    discovery::{DiscoveryMutability, DiscoveryRoots, discover_all},
    mutation::{TogglePlanRequest, ToggleStatus, plan_toggle},
    providers::{ProviderId, registry::provider_registry},
};

fn fixtures_root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

#[test]
fn registry_contains_each_current_provider_once() {
    let registry = provider_registry();
    let provider_ids = registry
        .iter()
        .map(|descriptor| descriptor.id)
        .collect::<Vec<_>>();

    assert_eq!(provider_ids, ProviderId::ALL);
    assert_eq!(
        provider_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        6
    );
    assert_eq!(registry.len(), 6);
}

#[test]
fn registry_is_authoritative_for_compatibility_capability_rows() {
    let registry = provider_registry();
    let matrix = load_capability_matrix(fixtures_root()).expect("capability matrix");

    assert_eq!(CAPABILITY_ROWS.len(), registry.len());
    for (descriptor, compatibility_row) in registry.iter().zip(CAPABILITY_ROWS) {
        let row = descriptor.capabilities;
        let fixture = &matrix.providers[descriptor.id.as_str()];

        assert_eq!(row, *compatibility_row);
        assert_eq!(row.provider_id, descriptor.id.as_str());
        assert_eq!(row.skills, fixture.skills);
        assert_eq!(row.configured_mcps, fixture.configured_mcps);
        assert_eq!(row.tools, fixture.tools);
        assert_eq!(row.agents, fixture.agents);
        assert_eq!(row.hooks, fixture.hooks);
        assert_eq!(row.provider_settings, fixture.provider_settings);
        assert_eq!(row.plugin_configs, fixture.plugin_configs);
        assert_eq!(row.plugin_manifests, fixture.plugin_manifests);
        assert_eq!(row.plugin_global_scope, fixture.plugin_global_scope);
        assert_eq!(row.plugin_project_scope, fixture.plugin_project_scope);
        assert_eq!(row.extensions, fixture.extensions);
        assert_eq!(row.note, matrix.notes[descriptor.id.as_str()]);
    }
}

#[test]
fn provider_global_and_project_roots_cover_every_registry_provider() {
    let roots = DiscoveryRoots::fixture_root(fixtures_root());
    for provider in ProviderId::ALL {
        let global = roots.provider_global_root(provider);
        let project = roots.provider_project_root(provider);
        assert!(
            global.starts_with(fixtures_root()),
            "{provider:?} global root escaped the fixture tree: {}",
            global.display()
        );
        assert!(
            project.starts_with(fixtures_root()),
            "{provider:?} project root escaped the fixture tree: {}",
            project.display()
        );
        assert_ne!(
            global, project,
            "{provider:?} global and project roots collided"
        );
    }
    assert_eq!(
        roots.provider_global_root(ProviderId::Cursor),
        roots.cursor_config.as_path()
    );
}

#[test]
fn every_fixture_readwrite_item_has_a_toggle_plan() {
    let roots = DiscoveryRoots::fixture_root(fixtures_root());
    let discovery = discover_all(&roots).expect("fixture discovery");
    let app_state_root = tempfile::TempDir::new().expect("temporary app state");
    let blocked = discovery
        .items
        .iter()
        .filter(|item| item.mutability == DiscoveryMutability::ReadWrite)
        .filter_map(|item| {
            let result = plan_toggle(TogglePlanRequest {
                app_state_root: app_state_root.path().to_path_buf(),
                item: item.clone(),
            });
            (result.status == ToggleStatus::Blocked).then(|| {
                format!(
                    "{} ({:?}/{:?}): {}",
                    item.id,
                    item.provider,
                    item.category,
                    result.reason.unwrap_or_else(|| "no reason".to_string())
                )
            })
        })
        .collect::<Vec<_>>();

    assert!(
        blocked.is_empty(),
        "read-write fixture items must be plannable so a new provider cannot silently miss mutation dispatch:\n{}",
        blocked.join("\n")
    );
}
