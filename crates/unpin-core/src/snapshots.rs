use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::clock::{current_timestamp, unix_nanos_id};
use crate::config::{
    get_latest_snapshot_path as latest_snapshot_path,
    get_snapshot_history_dir as snapshot_history_dir,
};
use crate::control::{CONTROL_STATUS_SCHEMA_VERSION, PersistentControlMetadata};
use crate::discovery::{
    DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryOutput,
    DiscoveryWarning, ProviderId,
};
use crate::fs_support::{read_optional_dir, read_optional_string};

pub type SnapshotError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct SnapshotWriteOptions {
    pub app_state_root: PathBuf,
    pub project_root: PathBuf,
    pub discovery: DiscoveryOutput,
    pub captured_at: Option<String>,
    pub id: Option<String>,
    pub max_history: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySnapshot {
    pub version: u8,
    pub id: String,
    pub captured_at: String,
    pub project_root: String,
    pub items: Vec<DiscoveryItem>,
    pub warnings: Vec<DiscoveryWarning>,
    pub inventory: DiscoveryInventorySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<PersistentControlMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryInventorySummary {
    pub providers: Vec<ProviderInventorySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInventorySummary {
    pub provider: ProviderId,
    pub total_available: usize,
    pub total_active: usize,
    pub warning_count: usize,
    #[serde(default)]
    pub kinds: BTreeMap<String, InventoryBucketSummary>,
    #[serde(default)]
    pub categories: BTreeMap<String, InventoryBucketSummary>,
    #[serde(default)]
    pub layers: BTreeMap<String, InventoryBucketSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryBucketSummary {
    pub available: usize,
    pub active: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotWriteResult {
    pub snapshot: DiscoverySnapshot,
    pub latest_path: PathBuf,
    pub history_path: PathBuf,
}

pub fn write_discovery_snapshot(
    options: SnapshotWriteOptions,
) -> Result<SnapshotWriteResult, SnapshotError> {
    write_snapshot(options, None)
}

pub fn write_control_snapshot(
    options: SnapshotWriteOptions,
    control: PersistentControlMetadata,
) -> Result<SnapshotWriteResult, SnapshotError> {
    write_snapshot(options, Some(control))
}

fn write_snapshot(
    options: SnapshotWriteOptions,
    control: Option<PersistentControlMetadata>,
) -> Result<SnapshotWriteResult, SnapshotError> {
    if options.max_history == 0 {
        return Err("snapshot max_history must be positive".into());
    }

    let captured_at = match options.captured_at {
        Some(captured_at) => captured_at,
        None => current_timestamp()?,
    };
    let id = match options.id {
        Some(id) => id,
        None => current_snapshot_id()?,
    };
    let latest_path = latest_snapshot_path(&options.app_state_root, &options.project_root);
    let history_dir = snapshot_history_dir(&options.app_state_root, &options.project_root);
    let history_path = history_dir.join(format!("{id}.json"));
    let mut history_entries = read_history(&history_dir)?;
    let snapshot = build_discovery_snapshot(
        id,
        captured_at,
        &options.project_root,
        options.discovery,
        control,
    );
    let json = deterministic_json(&snapshot)?;

    fs::create_dir_all(&history_dir)?;
    fs::create_dir_all(
        latest_path
            .parent()
            .expect("latest snapshot path has a parent"),
    )?;
    fs::write(&history_path, &json)?;
    history_entries.push(HistoryEntry {
        path: history_path.clone(),
        snapshot: snapshot.clone(),
    });
    prune_history_entries(history_entries, options.max_history)?;
    fs::write(&latest_path, json)?;

    Ok(SnapshotWriteResult {
        snapshot,
        latest_path,
        history_path,
    })
}

pub fn list_snapshot_history(
    app_state_root: &Path,
    project_root: &Path,
) -> Result<Vec<DiscoverySnapshot>, SnapshotError> {
    let history_dir = snapshot_history_dir(app_state_root, project_root);
    read_history(&history_dir).map(|entries| {
        entries
            .into_iter()
            .map(|entry| entry.snapshot)
            .collect::<Vec<_>>()
    })
}

pub fn load_latest_discovery_snapshot(
    app_state_root: &Path,
    project_root: &Path,
) -> Result<Option<DiscoverySnapshot>, SnapshotError> {
    let latest_path = latest_snapshot_path(app_state_root, project_root);
    let Some(raw) = read_optional_string(&latest_path)? else {
        return Ok(None);
    };
    parse_snapshot(&latest_path, &raw).map(Some)
}

fn build_discovery_snapshot(
    id: String,
    captured_at: String,
    project_root: &Path,
    mut discovery: DiscoveryOutput,
    control: Option<PersistentControlMetadata>,
) -> DiscoverySnapshot {
    for item in &mut discovery.items {
        if let Some(hook) = &mut item.hook {
            hook.trust = crate::hooks::HookTrustState::NeedsReview;
        }
    }
    sort_discovery_items(&mut discovery.items);
    sort_discovery_warnings(&mut discovery.warnings);

    let inventory = build_inventory_summary(&discovery);

    DiscoverySnapshot {
        version: if control.is_some() { 2 } else { 1 },
        id,
        captured_at,
        project_root: project_root.to_string_lossy().into_owned(),
        items: discovery.items,
        warnings: discovery.warnings,
        inventory,
        control,
    }
}

pub fn build_inventory_summary(discovery: &DiscoveryOutput) -> DiscoveryInventorySummary {
    let mut provider_items = BTreeMap::<&'static str, ProviderInventorySummary>::new();

    for provider in ProviderId::ALL {
        provider_items.insert(
            provider.as_str(),
            ProviderInventorySummary {
                provider,
                total_available: 0,
                total_active: 0,
                warning_count: discovery
                    .warnings
                    .iter()
                    .filter(|warning| warning.provider == provider)
                    .count(),
                kinds: empty_kind_summary(),
                categories: empty_category_summary(),
                layers: empty_layer_summary(),
            },
        );
    }

    for item in &discovery.items {
        let summary = provider_items
            .get_mut(item.provider.as_str())
            .expect("provider summary exists");
        summary.total_available += 1;
        increment_available(&mut summary.kinds, item.kind.as_str());
        increment_available(&mut summary.categories, item.category.as_str());
        increment_available(&mut summary.layers, item.layer.as_str());
        if item.enabled {
            summary.total_active += 1;
            increment_active(&mut summary.kinds, item.kind.as_str());
            increment_active(&mut summary.categories, item.category.as_str());
            increment_active(&mut summary.layers, item.layer.as_str());
        }
    }

    DiscoveryInventorySummary {
        providers: ProviderId::ALL
            .into_iter()
            .filter_map(|provider| provider_items.remove(provider.as_str()))
            .collect(),
    }
}

fn empty_kind_summary() -> BTreeMap<String, InventoryBucketSummary> {
    [
        DiscoveryKind::Skill,
        DiscoveryKind::Mcp,
        DiscoveryKind::Plugin,
        DiscoveryKind::Agent,
        DiscoveryKind::Hook,
        DiscoveryKind::Setting,
    ]
    .into_iter()
    .map(|kind| (kind.as_str().to_string(), InventoryBucketSummary::default()))
    .collect()
}

fn empty_category_summary() -> BTreeMap<String, InventoryBucketSummary> {
    [
        DiscoveryCategory::Skill,
        DiscoveryCategory::ConfiguredMcp,
        DiscoveryCategory::Tool,
        DiscoveryCategory::Agent,
        DiscoveryCategory::Hook,
        DiscoveryCategory::ProviderSetting,
        DiscoveryCategory::PluginConfig,
        DiscoveryCategory::PluginManifest,
    ]
    .into_iter()
    .map(|category| {
        (
            category.as_str().to_string(),
            InventoryBucketSummary::default(),
        )
    })
    .collect()
}

fn empty_layer_summary() -> BTreeMap<String, InventoryBucketSummary> {
    [DiscoveryLayer::Global, DiscoveryLayer::Project]
        .into_iter()
        .map(|layer| {
            (
                layer.as_str().to_string(),
                InventoryBucketSummary::default(),
            )
        })
        .collect()
}

fn increment_available(buckets: &mut BTreeMap<String, InventoryBucketSummary>, key: &'static str) {
    buckets.entry(key.to_string()).or_default().available += 1;
}

fn increment_active(buckets: &mut BTreeMap<String, InventoryBucketSummary>, key: &'static str) {
    buckets.entry(key.to_string()).or_default().active += 1;
}

fn deterministic_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value).map(|json| format!("{json}\n"))
}

struct HistoryEntry {
    path: PathBuf,
    snapshot: DiscoverySnapshot,
}

fn read_history(history_dir: &Path) -> Result<Vec<HistoryEntry>, SnapshotError> {
    let Some(read_dir) = read_optional_dir(history_dir)? else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }

        let snapshot = parse_snapshot_file(&path)?;
        entries.push(HistoryEntry { path, snapshot });
    }

    entries.sort_by(|left, right| {
        right
            .snapshot
            .captured_at
            .cmp(&left.snapshot.captured_at)
            .then_with(|| right.snapshot.id.cmp(&left.snapshot.id))
    });
    Ok(entries)
}

fn parse_snapshot_file(path: &Path) -> Result<DiscoverySnapshot, SnapshotError> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "invalid snapshot file {}: {}",
            path.to_string_lossy(),
            error
        )
    })?;
    parse_snapshot(path, &raw)
}

fn parse_snapshot(path: &Path, raw: &str) -> Result<DiscoverySnapshot, SnapshotError> {
    let snapshot = serde_json::from_str::<DiscoverySnapshot>(raw).map_err(|error| {
        format!(
            "invalid snapshot file {}: {}",
            path.to_string_lossy(),
            error
        )
    })?;
    validate_snapshot(&snapshot).map_err(|error| {
        format!(
            "invalid snapshot file {}: {}",
            path.to_string_lossy(),
            error
        )
    })?;
    let mut snapshot = snapshot;
    sort_discovery_items(&mut snapshot.items);
    sort_discovery_warnings(&mut snapshot.warnings);
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &DiscoverySnapshot) -> Result<(), String> {
    if !matches!(snapshot.version, 1 | 2) {
        return Err(format!(
            "unsupported snapshot schema version: {}",
            snapshot.version
        ));
    }
    match (snapshot.version, &snapshot.control) {
        (1, None) => {}
        (1, Some(_)) => {
            return Err("snapshot version 1 cannot contain control metadata".to_string());
        }
        (2, Some(control)) if control.schema_version == CONTROL_STATUS_SCHEMA_VERSION => {}
        (2, Some(control)) => {
            return Err(format!(
                "unsupported control metadata schema version: {}",
                control.schema_version
            ));
        }
        (2, None) => return Err("snapshot version 2 requires control metadata".to_string()),
        _ => unreachable!("snapshot version was validated"),
    }
    if snapshot.id.is_empty() {
        return Err("snapshot id must be a non-empty string".to_string());
    }
    if OffsetDateTime::parse(&snapshot.captured_at, &Rfc3339).is_err() {
        return Err("snapshot capturedAt must be a valid RFC3339 timestamp".to_string());
    }
    if snapshot.project_root.is_empty() {
        return Err("snapshot projectRoot must be a non-empty string".to_string());
    }

    let expected_inventory = build_inventory_summary(&DiscoveryOutput {
        items: snapshot.items.clone(),
        warnings: snapshot.warnings.clone(),
        ..DiscoveryOutput::default()
    });
    if snapshot.inventory != expected_inventory {
        return Err("snapshot inventory does not match items and warnings".to_string());
    }

    Ok(())
}

fn sort_discovery_items(items: &mut [DiscoveryItem]) {
    items.sort_by(|left, right| {
        provider_rank(left.provider)
            .cmp(&provider_rank(right.provider))
            .then_with(|| layer_rank(left.layer).cmp(&layer_rank(right.layer)))
            .then_with(|| category_rank(left.category).cmp(&category_rank(right.category)))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn sort_discovery_warnings(warnings: &mut [DiscoveryWarning]) {
    warnings.sort_by(|left, right| {
        provider_rank(left.provider)
            .cmp(&provider_rank(right.provider))
            .then_with(|| optional_layer_rank(left.layer).cmp(&optional_layer_rank(right.layer)))
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
}

fn provider_rank(provider: ProviderId) -> u8 {
    ProviderId::ALL
        .iter()
        .position(|candidate| *candidate == provider)
        .expect("provider is registered") as u8
}

fn layer_rank(layer: DiscoveryLayer) -> u8 {
    match layer {
        DiscoveryLayer::Global => 0,
        DiscoveryLayer::Project => 1,
    }
}

fn optional_layer_rank(layer: Option<DiscoveryLayer>) -> u8 {
    layer.map_or(0, layer_rank)
}

fn category_rank(category: DiscoveryCategory) -> u8 {
    match category {
        DiscoveryCategory::Skill => 0,
        DiscoveryCategory::ConfiguredMcp => 1,
        DiscoveryCategory::Tool => 2,
        DiscoveryCategory::Agent => 3,
        DiscoveryCategory::Hook => 4,
        DiscoveryCategory::ProviderSetting => 5,
        DiscoveryCategory::PluginConfig => 6,
        DiscoveryCategory::PluginManifest => 7,
    }
}

fn prune_history_entries(
    mut entries: Vec<HistoryEntry>,
    max_history: usize,
) -> Result<(), SnapshotError> {
    entries.sort_by(|left, right| {
        right
            .snapshot
            .captured_at
            .cmp(&left.snapshot.captured_at)
            .then_with(|| right.snapshot.id.cmp(&left.snapshot.id))
    });

    for entry in entries.into_iter().skip(max_history) {
        fs::remove_file(entry.path)?;
    }

    Ok(())
}

fn current_snapshot_id() -> Result<String, String> {
    unix_nanos_id("snap")
}
