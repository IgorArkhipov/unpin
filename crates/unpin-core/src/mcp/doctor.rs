use super::*;

use serde_json::{Value, json};

pub(super) fn run_doctor_structured(context: &McpContext) -> Value {
    let matrix_issues = capability_matrix_issues(context.fixture_root.as_ref())
        .into_iter()
        .filter(|issue| capability_matrix_issue_in_scope(context.provider_scope, issue))
        .collect::<Vec<_>>();
    if !matrix_issues.is_empty() {
        let provider_issues = capability_matrix_provider_issues(&matrix_issues);
        return json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(context.provider_scope, "error", provider_issues),
            "capabilityMatrixIssues": matrix_issues,
            "fixtureIssues": [],
            "warnings": []
        });
    }

    let fixture_issues = provider_fixture_issues(context.fixture_root.as_ref())
        .into_iter()
        .filter(|issue| provider_issue_in_scope(context.provider_scope, issue, "providerId"))
        .collect::<Vec<_>>();
    if !fixture_issues.is_empty() {
        let provider_issues = fixture_provider_issues(&fixture_issues);
        return json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(context.provider_scope, "error", provider_issues),
            "fixtureIssues": fixture_issues,
            "warnings": []
        });
    }

    match discover_scoped_cached(context) {
        Ok(discovery) => {
            let provider_issues = discovery
                .warnings
                .iter()
                .map(discovery_warning_provider_issue)
                .collect::<Vec<_>>();
            json!({
                "status": if provider_issues.is_empty() { "ok" } else { "warning" },
                "packageRoot": context.package_root,
                "fixturesRoot": context.fixture_root,
                "providers": provider_health_rows(context.provider_scope, "warning", provider_issues),
                "itemsDiscovered": discovery.items.len(),
                "warnings": discovery.warnings
            })
        }
        Err(error) => json!({
            "status": "error",
            "packageRoot": context.package_root,
            "fixturesRoot": context.fixture_root,
            "providers": provider_health_rows(
                context.provider_scope,
                "error",
                discovery_error_provider_issues(context.provider_scope, &error.to_string())
            ),
            "itemsDiscovered": 0,
            "warnings": [],
            "reason": error.to_string()
        }),
    }
}
