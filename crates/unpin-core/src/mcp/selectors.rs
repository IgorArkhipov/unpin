use super::*;

use serde_json::{Value, json};

pub(super) fn provider_issue_in_scope(scope: McpProviderScope, issue: &Value, field: &str) -> bool {
    scope
        .provider()
        .is_none_or(|provider| issue.get(field).and_then(Value::as_str) == Some(provider.as_str()))
}

pub(super) fn capability_matrix_issue_in_scope(scope: McpProviderScope, issue: &Value) -> bool {
    scope.provider().is_none_or(|provider| {
        issue
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| provider_ids_from_message(message).contains(&provider.as_str()))
    })
}

pub(super) fn provider_ids_from_message(message: &str) -> Vec<&'static str> {
    let providers = ProviderId::ALL
        .into_iter()
        .map(ProviderId::as_str)
        .filter(|provider| message.contains(provider))
        .collect::<Vec<_>>();

    if providers.is_empty() {
        ProviderId::ALL.map(ProviderId::as_str).to_vec()
    } else {
        providers
    }
}

pub(super) fn provider_summaries(
    discovery: &DiscoveryOutput,
    arguments: &Value,
    scope: McpProviderScope,
) -> Vec<Value> {
    let mut summaries = build_inventory_summary(discovery)
        .providers
        .into_iter()
        .map(|summary| serde_json::to_value(summary).expect("provider summary serializes"))
        .collect::<Vec<_>>();
    summaries.retain(|summary| {
        summary
            .get("provider")
            .and_then(Value::as_str)
            .is_some_and(|provider| {
                parse_provider_id(provider).is_ok_and(|provider| scope.allows(provider))
                    && selector_array_matches(arguments, "providers", provider)
            })
    });
    summaries
}

pub(super) fn filter_summary_discovery(
    mut discovery: DiscoveryOutput,
    arguments: &Value,
) -> DiscoveryOutput {
    discovery.items.retain(|item| {
        selector_array_matches(arguments, "providers", item.provider.as_str())
            && selector_array_matches(arguments, "layers", item.layer.as_str())
    });
    discovery.warnings.retain(|warning| {
        selector_array_matches(arguments, "providers", warning.provider.as_str())
            && warning
                .layer
                .is_none_or(|layer| selector_array_matches(arguments, "layers", layer.as_str()))
    });
    discovery
}

pub(super) fn selector_matches(item: &DiscoveryItem, selector: &Value) -> bool {
    selector_array_matches(selector, "providers", item.provider.as_str())
        && selector_array_matches(selector, "kinds", item.kind.as_str())
        && selector_array_matches(selector, "categories", item.category.as_str())
        && selector_array_matches(selector, "layers", item.layer.as_str())
        && selector_array_matches(selector, "ids", &item.id)
        && selector
            .get("enabled")
            .and_then(Value::as_bool)
            .is_none_or(|enabled| enabled == item.enabled)
}

pub(super) fn validate_selector(selector: &Value) -> Result<(), String> {
    if selector.is_null() {
        return Ok(());
    }

    let selector = selector
        .as_object()
        .ok_or_else(|| "selector must be an object".to_string())?;

    for field in ["providers", "kinds", "categories", "layers", "ids"] {
        validate_selector_array_field(selector.get(field), field)?;
    }

    if let Some(enabled) = selector.get("enabled")
        && !enabled.is_boolean()
    {
        return Err("selector.enabled must be a boolean".to_string());
    }

    Ok(())
}

pub(super) fn validate_selector_array_field(
    value: Option<&Value>,
    field: &str,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| format!("selector.{field} must be an array of strings"))?;
    if entries.iter().any(|entry| !entry.is_string()) {
        return Err(format!("selector.{field} must be an array of strings"));
    }

    Ok(())
}

pub(super) fn selector_array_matches(selector: &Value, field: &str, value: &str) -> bool {
    selector
        .get(field)
        .and_then(Value::as_array)
        .is_none_or(|entries| entries.iter().any(|entry| entry.as_str() == Some(value)))
}

#[allow(dead_code)]
pub(super) fn canonical_selector(selector: &Value) -> Value {
    let Some(selector_object) = selector.as_object() else {
        return json!({});
    };
    let mut canonical = serde_json::Map::new();

    for field in ["providers", "kinds", "categories", "layers", "ids"] {
        if let Some(values) = selector_object.get(field).and_then(Value::as_array) {
            let mut strings = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            strings.sort();
            canonical.insert(field.to_string(), json!(strings));
        }
    }

    if let Some(enabled) = selector_object.get("enabled").and_then(Value::as_bool) {
        canonical.insert("enabled".to_string(), json!(enabled));
    }

    Value::Object(canonical)
}

pub(super) fn bulk_plan_fingerprint(payload: Value) -> String {
    let canonical = serde_json::to_vec(&payload).expect("bulk plan payload serializes");
    let digest = Sha256::digest(canonical);
    format!("sha256:{}", hex_bytes(&digest))
}

pub(super) fn hex_bytes(bytes: &[u8]) -> String {
    pub(super) const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}
