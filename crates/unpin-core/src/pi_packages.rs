use std::collections::BTreeSet;

use serde_json::Value;

pub(crate) fn pi_package_extension_state(package: &Value) -> Result<(&str, bool), &'static str> {
    // Pi package filters load all resources when a key is omitted and none when it is `[]`.
    if let Some(source) = package.as_str() {
        return if source.is_empty() {
            Err("must use a non-empty source string")
        } else {
            Ok((source, true))
        };
    }

    let Some(package) = package.as_object() else {
        return Err("must be a source string or object");
    };
    let Some(source) = package
        .get("source")
        .and_then(Value::as_str)
        .filter(|source| !source.is_empty())
    else {
        return Err("object must contain a non-empty source string");
    };
    let Some(extensions) = package.get("extensions") else {
        return Ok((source, true));
    };
    let Some(extensions) = extensions.as_array() else {
        return Err("extensions filter must be an array");
    };
    let mut names = BTreeSet::new();
    if !extensions.iter().all(|extension| {
        extension
            .as_str()
            .filter(|extension| !extension.is_empty())
            .is_some_and(|extension| names.insert(extension))
    }) {
        return Err("extensions filter must contain unique non-empty strings");
    }
    Ok((source, !extensions.is_empty()))
}

pub(crate) fn pi_disabled_package_entry(package: &Value) -> Result<Option<Value>, &'static str> {
    let (source, enabled) = pi_package_extension_state(package)?;
    if !enabled {
        return Ok(None);
    }
    let mut object = package.as_object().cloned().unwrap_or_else(|| {
        let mut object = serde_json::Map::new();
        object.insert("source".to_string(), Value::String(source.to_string()));
        object
    });
    object.insert("extensions".to_string(), Value::Array(Vec::new()));
    Ok(Some(Value::Object(object)))
}
