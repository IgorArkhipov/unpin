use std::{
    fs,
    path::{Path, PathBuf},
};

use tempfile::TempDir as RawTempDir;
use unpin_core::{
    catalog::{
        CapabilityKind, CatalogWarningCode, ContributionControl,
        model::CapabilityLifecycle,
        store::{CatalogStore, CatalogStoreError},
    },
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput,
    },
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary directory");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private temporary directory");
        }
        Self {
            _inner: inner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn item(
    provider: ProviderId,
    kind: DiscoveryKind,
    category: DiscoveryCategory,
    id: &str,
    display_name: &str,
    source_path: &Path,
) -> DiscoveryItem {
    DiscoveryItem {
        provider,
        kind,
        category,
        layer: DiscoveryLayer::Global,
        id: id.to_string(),
        display_name: display_name.to_string(),
        enabled: true,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: source_path.to_string_lossy().into_owned(),
        state_path: source_path.to_string_lossy().into_owned(),
        source_fingerprint: Some(format!("fingerprint-{display_name}")),
        hook: None,
    }
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("catalog-test", 1).expect("valid owner")
}

#[test]
fn shared_skill_becomes_one_capability_with_disclosed_provider_fan_out() {
    let temp = TempDir::new();
    let skill = temp.path().join(".agents/skills/review");
    fs::create_dir_all(&skill).expect("shared skill directory");
    let mut claude_project = item(
        ProviderId::Claude,
        DiscoveryKind::Skill,
        DiscoveryCategory::Skill,
        "claude:project:skill:review",
        "review",
        &skill,
    );
    claude_project.layer = DiscoveryLayer::Project;
    let output = DiscoveryOutput {
        items: vec![
            item(
                ProviderId::Claude,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                "claude:global:skill:review",
                "review",
                &skill,
            ),
            item(
                ProviderId::Codex,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                "codex:global:skill:review",
                "review",
                &skill,
            ),
            item(
                ProviderId::Zed,
                DiscoveryKind::Skill,
                DiscoveryCategory::Skill,
                "zed:global:skill:review",
                "review",
                &skill,
            ),
            claude_project,
        ],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    };

    let catalog = output.to_catalog().expect("catalog projection");
    assert_eq!(catalog.records.len(), 1);
    let record = catalog.records.values().next().expect("shared skill");
    assert_eq!(record.kind, CapabilityKind::Skill);
    assert_eq!(record.provider_fan_out(), 4);
    assert!(record.supports_provider(ProviderId::Claude));
    assert!(record.supports_provider(ProviderId::Codex));
    assert!(record.supports_provider(ProviderId::Zed));
    assert_eq!(record.lifecycle, CapabilityLifecycle::discovered(true));
    assert!(record.lifecycle.cataloged);
    assert!(record.lifecycle.installed);
    assert!(record.lifecycle.active);
    assert!(record.lifecycle.exposed);
    assert!(!record.lifecycle.loaded);
    assert!(!record.lifecycle.connected);
}

#[test]
fn static_manifest_is_parsed_as_data_and_dynamic_plugin_stays_atomic() {
    let temp = TempDir::new();
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unpin/catalog");
    let sentinel = temp.path().join("must-not-exist");
    let raw = fs::read_to_string(fixture_root.join("static-plugin.json"))
        .expect("static plugin fixture")
        .replace(
            "/tmp/unpin-must-not-execute",
            sentinel.to_string_lossy().as_ref(),
        );
    let static_manifest = temp.path().join("static-plugin.json");
    fs::write(&static_manifest, raw).expect("temporary static manifest");
    let dynamic_manifest = fixture_root.join("dynamic-plugin.js");
    let invalid_manifest = temp.path().join("invalid-plugin.json");
    fs::write(&invalid_manifest, "{").expect("invalid manifest fixture");
    let oversized_manifest = temp.path().join("oversized-plugin.json");
    fs::write(&oversized_manifest, vec![b' '; 1_048_577]).expect("oversized manifest fixture");
    let empty_manifest = temp.path().join("empty-plugin.json");
    fs::write(&empty_manifest, r#"{"name":"empty","contributions":{}}"#)
        .expect("empty manifest fixture");
    let output = DiscoveryOutput {
        items: vec![
            item(
                ProviderId::Claude,
                DiscoveryKind::Plugin,
                DiscoveryCategory::PluginManifest,
                "claude:global:plugin:review",
                "review-connector",
                &static_manifest,
            ),
            item(
                ProviderId::OpenCode,
                DiscoveryKind::Plugin,
                DiscoveryCategory::PluginManifest,
                "opencode:global:plugin:dynamic",
                "dynamic-plugin",
                &dynamic_manifest,
            ),
            item(
                ProviderId::Cursor,
                DiscoveryKind::Plugin,
                DiscoveryCategory::PluginManifest,
                "cursor:global:plugin:invalid",
                "invalid-plugin",
                &invalid_manifest,
            ),
            item(
                ProviderId::Codex,
                DiscoveryKind::Plugin,
                DiscoveryCategory::PluginManifest,
                "codex:global:plugin:oversized",
                "oversized-plugin",
                &oversized_manifest,
            ),
            item(
                ProviderId::Pi,
                DiscoveryKind::Plugin,
                DiscoveryCategory::PluginManifest,
                "pi:global:plugin:empty",
                "empty-plugin",
                &empty_manifest,
            ),
        ],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    };

    let catalog = output.to_catalog().expect("catalog projection");
    assert!(!sentinel.exists(), "manifest code must never execute");
    let static_plugin = catalog
        .records
        .values()
        .find(|record| record.display_name == "review-connector")
        .expect("static plugin");
    assert_eq!(static_plugin.contributions.len(), 3);
    assert!(
        static_plugin
            .contributions
            .iter()
            .all(|edge| edge.control == ContributionControl::Atomic)
    );
    for edge in &static_plugin.contributions {
        let contribution = catalog
            .get(&edge.capability_id)
            .expect("contributed capability");
        assert_eq!(
            contribution.contributed_by.as_ref(),
            Some(&static_plugin.id)
        );
        assert_eq!(contribution.provider_fan_out(), 1);
    }

    let dynamic_plugin = catalog
        .records
        .values()
        .find(|record| record.display_name == "dynamic-plugin")
        .expect("dynamic plugin");
    assert!(dynamic_plugin.atomic_unknown_contributions);
    assert!(catalog.warnings.iter().any(|warning| {
        warning.capability_id == dynamic_plugin.id
            && warning.code == CatalogWarningCode::UnknownDynamicContributions
    }));
    assert!(
        catalog
            .warnings
            .iter()
            .any(|warning| warning.code == CatalogWarningCode::InvalidManifest)
    );
    assert!(
        catalog
            .warnings
            .iter()
            .any(|warning| warning.code == CatalogWarningCode::OversizedManifest)
    );
    let empty_plugin = catalog
        .records
        .values()
        .find(|record| record.display_name == "empty-plugin")
        .expect("empty plugin");
    assert!(empty_plugin.contributions.is_empty());
    assert!(!empty_plugin.atomic_unknown_contributions);
    assert!(
        !catalog
            .warnings
            .iter()
            .any(|warning| warning.capability_id == empty_plugin.id)
    );
}

#[test]
fn discovered_mcp_tools_receive_deterministic_collision_namespaces() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}\n").expect("MCP source");
    let catalog = DiscoveryOutput {
        items: vec![
            item(
                ProviderId::Claude,
                DiscoveryKind::Mcp,
                DiscoveryCategory::Tool,
                "claude:global:tool:review:run-one",
                "run",
                &source,
            ),
            item(
                ProviderId::Claude,
                DiscoveryKind::Mcp,
                DiscoveryCategory::Tool,
                "claude:global:tool:review:run-two",
                "run",
                &source,
            ),
        ],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    }
    .to_catalog()
    .expect("tool catalog");
    let namespaces = catalog
        .records
        .values()
        .map(|record| record.tool_namespace.clone().expect("tool namespace"))
        .collect::<Vec<_>>();
    assert_eq!(namespaces.len(), 2);
    assert_eq!(namespaces[0], namespaces[1]);
}

#[test]
fn catalog_store_materializes_content_addressed_objects_and_atomic_index() {
    let temp = TempDir::new();
    let source = temp.path().join("skill");
    fs::create_dir(&source).expect("skill source");
    let catalog = DiscoveryOutput {
        items: vec![item(
            ProviderId::Claude,
            DiscoveryKind::Skill,
            DiscoveryCategory::Skill,
            "claude:global:skill:review",
            "review",
            &source,
        )],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    }
    .to_catalog()
    .expect("catalog projection");
    let store = CatalogStore::new(temp.path().join("state"));

    let first = store
        .materialize(&catalog, owner())
        .expect("first materialization");
    let second = store
        .materialize(&catalog, owner())
        .expect("idempotent materialization");
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.object_revision, second.object_revision);
    assert_eq!(first.index_revision, second.index_revision);
    assert_eq!(
        store.load(&first.digest).expect("load catalog object"),
        Some(catalog)
    );
    let index = store
        .load_index()
        .expect("load catalog index")
        .expect("catalog index");
    assert_eq!(
        index.value.latest_digest.as_deref(),
        Some(first.digest.as_str())
    );
    assert_eq!(index.value.object_digests.len(), 1);
}

#[test]
fn missing_catalog_object_is_a_read_only_miss() {
    let temp = TempDir::new();
    let state = temp.path().join("state");
    fs::create_dir(&state).expect("state root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).expect("private state root");
    }
    let store = CatalogStore::new(state);
    assert_eq!(store.load(&"a".repeat(64)).expect("missing object"), None);
    assert!(matches!(
        store.load("../outside"),
        Err(CatalogStoreError::InvalidDigest { .. })
    ));
}
