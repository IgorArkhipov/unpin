use std::{collections::BTreeSet, path::Path};

use unpin_core::{
    capabilities::{CAPABILITY_ROWS, load_capability_matrix},
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
