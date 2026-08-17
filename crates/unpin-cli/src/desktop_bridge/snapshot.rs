use super::*;

use serde_json::{Value, json};

pub(super) fn recovery_snapshot_response(
    context: &DesktopBridgeContext,
) -> Result<Value, &'static str> {
    let backup_key = backup_authentication_key(context);
    let backup_index = backup_key
        .as_ref()
        .ok()
        .map(|key| load_backup_index_authenticated(&context.config.app_state_root, Some(key)));
    let (backups, backup_status) = match backup_index.as_ref() {
        Some(index) => (
            index
                .summaries()
                .iter()
                .map(redacted_backup_summary)
                .collect::<Vec<_>>(),
            if index.is_complete() {
                "available"
            } else {
                "unavailable"
            },
        ),
        None => (Vec::new(), "unavailable"),
    };
    let (mut operations, control_operation_status) = control_operation_summaries(context);
    let (group_operations, group_operation_status) =
        group_operation_summaries(context, backup_key.as_ref().ok(), backup_index.as_ref());
    operations.extend(group_operations);
    operations.sort_by(|left, right| {
        left["operationId"]
            .as_str()
            .cmp(&right["operationId"].as_str())
    });
    let operation_status =
        if control_operation_status == "available" && group_operation_status == "available" {
            "available"
        } else {
            "unavailable"
        };
    Ok(json!({
        "backups": backups,
        "backupStatus": backup_status,
        "operations": operations,
        "operationStatus": operation_status,
        "groupOperationStatus": group_operation_status,
    }))
}

pub(super) fn control_operation_summaries(
    context: &DesktopBridgeContext,
) -> (Vec<Value>, &'static str) {
    let Ok(session_key) = session_authority_key(context) else {
        return (Vec::new(), "unavailable");
    };
    let Ok(discovery) = cached_discovery(context) else {
        return (Vec::new(), "unavailable");
    };
    let Ok(status) = build_control_status(
        &discovery,
        &context.config.app_state_root,
        &context.config.project_root,
        &session_key,
    ) else {
        return (Vec::new(), "unavailable");
    };
    (
        status
            .operations
            .iter()
            .map(redacted_operation_summary)
            .collect(),
        "available",
    )
}

pub(super) fn group_operation_summaries(
    context: &DesktopBridgeContext,
    backup_key: Option<&BackupAuthenticationKey>,
    backup_index: Option<&AuthenticatedBackupIndex>,
) -> (Vec<Value>, &'static str) {
    let Some(backup_key) = backup_key else {
        return (Vec::new(), "unavailable");
    };
    let Ok(group_context) = group_access_context(context) else {
        return (Vec::new(), "unavailable");
    };
    let inspections = match backup_index {
        Some(backup_index) => list_group_operation_inspections_with_backup_index(
            group_context.app_state_root(),
            backup_key.clone(),
            group_context.repository_key(),
            group_context.workspace_key(),
            backup_index,
        ),
        None => list_group_operation_inspections(
            group_context.app_state_root(),
            backup_key.clone(),
            group_context.repository_key(),
            group_context.workspace_key(),
        ),
    };
    match inspections {
        Ok(operations) => (
            operations
                .iter()
                .map(redacted_group_operation_summary)
                .collect(),
            "available",
        ),
        Err(
            unpin_core::groups::GroupOperationError::Authentication(_)
            | unpin_core::groups::GroupOperationError::AuthenticationFailed,
        ) => (Vec::new(), "authentication-unavailable"),
        Err(unpin_core::groups::GroupOperationError::ContextMismatch) => {
            (Vec::new(), "context-unavailable")
        }
        Err(unpin_core::groups::GroupOperationError::State(_)) => (Vec::new(), "state-unavailable"),
        Err(unpin_core::groups::GroupOperationError::Io(_)) => (Vec::new(), "storage-unavailable"),
        Err(
            unpin_core::groups::GroupOperationError::InvalidOperationId
            | unpin_core::groups::GroupOperationError::InvalidRecord
            | unpin_core::groups::GroupOperationError::InvalidBackupIndex
            | unpin_core::groups::GroupOperationError::Json(_)
            | unpin_core::groups::GroupOperationError::Clock(_),
        ) => (Vec::new(), "evidence-invalid"),
    }
}

pub(super) fn redacted_backup_summary(summary: &unpin_core::mutation::BackupSummary) -> Value {
    json!({
        "backupId": summary.backup_id,
        "createdAt": summary.created_at,
        "itemCount": summary.item_count,
        "providers": summary.providers,
        "layers": summary.layers,
        "restorable": summary.restorable,
        "authentication": summary.authentication,
        "targetEnabled": summary.target_enabled,
    })
}

pub(super) fn redacted_operation_summary(
    operation: &unpin_core::control::ControlOperationStatus,
) -> Value {
    json!({
        "operationId": operation.operation_id,
        "operationKind": operation.operation_kind,
        "lifecycle": operation.lifecycle,
        "effectGraphDigest": operation.effect_graph_digest,
        "authorizationRecorded": operation.authorization_recorded,
        "terminalCode": operation.terminal_code,
        "recoveryRequired": operation.recovery_required,
        "resourceCount": operation.resources.len(),
    })
}

pub(super) fn redacted_group_operation_summary(
    inspection: &unpin_core::groups::GroupOperationInspection,
) -> Value {
    json!({
        "operationId": inspection.operation.operation_id,
        "operationKind": ReachAwareOperationFamily::GroupToggle.as_str(),
        "lifecycle": inspection.operation.lifecycle,
        "qualifiedName": inspection.operation.qualified_name,
        "requestedState": inspection.operation.requested_state,
        "createdAt": inspection.operation.created_at,
        "updatedAt": inspection.operation.updated_at,
        "effectGraphDigest": inspection.operation.plan_fingerprint,
        "authorizationRecorded": true,
        "providerReach": inspection.operation.provider_reach,
        "providerCoverage": inspection.operation.provider_coverage,
        "providerReachLifecycle": inspection.operation.provider_reach_lifecycle,
        "providerWritesStarted": inspection.operation.provider_writes_started,
        "recoveryRequired": inspection.operation.lifecycle
            == unpin_core::groups::GroupOperationLifecycle::RecoveryRequired,
        "resourceCount": inspection
            .cohort_backup_indexes
            .iter()
            .map(|cohort| cohort.resource_ids.len())
            .sum::<usize>(),
        "backupIds": inspection
            .cohort_backup_indexes
            .iter()
            .flat_map(|cohort| cohort.backup_ids.iter())
            .collect::<Vec<_>>(),
        "evidenceAvailable": inspection.evidence_available,
        "finalState": inspection.operation.terminal_result.as_ref().map(|result| result.final_state),
        "observationFresh": inspection.operation.terminal_result.as_ref().map(|result| result.observation_fresh),
        "observationReason": inspection.operation.terminal_result.as_ref().and_then(|result| result.observation_reason.as_ref()),
        "members": inspection.operation.terminal_result.as_ref().map(|result| &result.members),
    })
}

pub(super) fn redacted_restore_plan(plan: &RestoreControlPlan) -> Value {
    json!({
        "backupId": plan.backup_id,
        "providers": plan.providers,
        "authentication": plan.authentication,
        "affectedResourceIds": plan.affected_resources.iter().map(|resource| &resource.resource_id).collect::<Vec<_>>(),
        "planFingerprint": plan.plan_fingerprint,
    })
}

pub(super) fn redacted_restore_result(result: &RestoreResult) -> Value {
    json!({
        "status": result.status,
        "backupId": result.backup_id,
        "affectedTargetCount": result.affected_targets.len(),
    })
}

pub(super) fn snapshot_response(context: &DesktopBridgeContext) -> Result<Value, &'static str> {
    let discovery = cached_discovery(context)?;
    let agent_plugins = discovery.agent_plugins();
    let resolver = group_resolver(context)?;
    let (groups, group_warnings) = resolver
        .list_views_with_warnings(&discovery)
        .map_err(|_| "group-state-unavailable")?;
    Ok(json!({
        "capturedAtUnix": unix_now(),
        "inventory": discovery.items.iter().map(redacted_item).collect::<Vec<_>>(),
        "warnings": discovery.warnings.iter().map(|warning| json!({
            "provider": warning.provider,
            "layer": warning.layer,
            "code": warning.code,
        })).collect::<Vec<_>>(),
        "agentPluginInventoryComplete": discovery.agent_plugin_inventory_complete(),
        "agentPlugins": agent_plugins.iter().map(redacted_agent_plugin_summary).collect::<Vec<_>>(),
        "groups": groups,
        "groupWarnings": group_warnings.iter().map(|warning| json!({
            "scope": warning.scope,
            "code": warning.code,
        })).collect::<Vec<_>>(),
    }))
}

pub(super) fn redacted_item(item: &DiscoveryItem) -> Value {
    json!({
        "provider": item.provider,
        "kind": item.kind,
        "category": item.category,
        "layer": item.layer,
        "id": item.id,
        "displayName": item.display_name,
        "enabled": item.enabled,
        "mutability": item.mutability,
    })
}

pub(super) fn redacted_agent_plugin_summary(package: &AgentPluginSummary) -> Value {
    let providers = package
        .instances
        .iter()
        .map(|instance| instance.provider)
        .collect::<BTreeSet<_>>();
    let component_kinds = package
        .instances
        .iter()
        .flat_map(|instance| instance.components.iter().map(|component| component.kind))
        .collect::<BTreeSet<_>>();
    json!({
        "logicalId": package.logical_id,
        "name": package.name,
        "componentSignature": package.component_signature,
        "projectionFingerprint": package.projection_fingerprint,
        "state": package.state,
        "access": package.access,
        "providers": providers,
        "componentKinds": component_kinds,
        "blockerCount": package.instances.iter().map(|instance| instance.blockers.len()).sum::<usize>(),
        "diagnosticCount": package.instances.iter().map(|instance| instance.diagnostics.len()).sum::<usize>(),
        "instanceCount": package.instances.len(),
        "instances": package.instances.iter().map(redacted_agent_plugin_instance).collect::<Vec<_>>(),
    })
}

pub(super) fn redacted_agent_plugin_instance(instance: &AgentPluginInstance) -> Value {
    json!({
        "instanceId": instance.instance_id,
        "provider": instance.provider,
        "layer": instance.layer,
        "state": instance.state,
        "access": instance.access,
        "version": instance.manifest.version,
        "components": instance.components.iter().map(|component| json!({
            "kind": component.kind,
            "name": component.name,
            "disposition": component.disposition,
            "reason": component.reason,
        })).collect::<Vec<_>>(),
        "activations": instance.activations.iter().map(|activation| json!({
            "enabled": activation.enabled,
            "mutability": activation.mutability,
        })).collect::<Vec<_>>(),
        "blockers": instance.blockers,
        "diagnostics": instance.diagnostics,
    })
}

pub(super) fn redacted_agent_plugin_plan(
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
    let mut value = redacted_agent_plugin_summary(package);
    value["operationId"] = json!(plan.operation_id);
    value["planFingerprint"] = json!(plan.plan_fingerprint);
    value["target"] = json!(if plan.target_enabled { "on" } else { "off" });
    value["providerReach"] = json!(plan.provider_reach);
    value["coverage"] = redacted_provider_coverage(&plan.provider_coverage);
    value["lifecycle"] = json!(plan.lifecycle);
    value["counts"] = redacted_agent_plugin_plan_counts(package, plan);
    value["review"] = redacted_agent_plugin_plan_review(package, plan);
    value
}

pub(super) fn redacted_agent_plugin_plan_counts(
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
    let activations = package
        .instances
        .iter()
        .map(|instance| instance.activations.len())
        .sum::<usize>();
    let components = package
        .instances
        .iter()
        .map(|instance| instance.components.len())
        .sum::<usize>();
    let diagnostics = package
        .instances
        .iter()
        .map(|instance| instance.blockers.len() + instance.diagnostics.len())
        .sum::<usize>();
    json!({
        "instances": package.instances.len(),
        "activations": activations,
        "components": components,
        "diagnostics": diagnostics,
        "included": plan.included_count(),
        "writes": plan.write_count(),
        "noOp": plan.included_count().saturating_sub(plan.write_count()),
        "blocked": plan.blocked_count(),
        "reachExcluded": plan.provider_coverage.reach_excluded_count(),
    })
}

pub(super) fn redacted_agent_plugin_plan_review(
    package: &AgentPluginSummary,
    plan: &BulkTogglePlan,
) -> Value {
    let included = plan
        .included
        .iter()
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
                "outcome": item.outcome,
            })
        })
        .collect::<Vec<_>>();
    let no_op = plan
        .included
        .iter()
        .filter(|item| item.outcome == IncludedTargetOutcome::NoOp)
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
            })
        })
        .collect::<Vec<_>>();
    let blocked = plan
        .blocked
        .iter()
        .map(|item| {
            json!({
                "provider": item.item.provider,
                "layer": item.item.layer,
                "reasonCode": item.reason_code,
            })
        })
        .collect::<Vec<_>>();
    let reach_excluded = package
        .instances
        .iter()
        .filter(|instance| !plan.provider_reach.allows(instance.provider))
        .map(|instance| {
            json!({
                "provider": instance.provider,
                "layer": instance.layer,
                "activationCount": instance.activations.len(),
                "reasonCode": "outside-selected-provider-reach",
            })
        })
        .collect::<Vec<_>>();
    let component_diagnostics = package
        .instances
        .iter()
        .flat_map(|instance| {
            let mut rows = instance
                .components
                .iter()
                .filter(|component| {
                    component.disposition != AgentPluginComponentDisposition::Available
                })
                .map(|component| {
                    json!({
                        "provider": instance.provider,
                        "layer": instance.layer,
                        "kind": component.kind,
                        "name": component.name,
                        "disposition": component.disposition,
                        "reason": component.reason,
                    })
                })
                .collect::<Vec<_>>();
            rows.extend(instance.blockers.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "blocked",
                    "reason": reason,
                })
            }));
            rows.extend(instance.diagnostics.iter().map(|reason| {
                json!({
                    "provider": instance.provider,
                    "layer": instance.layer,
                    "disposition": "diagnostic",
                    "reason": reason,
                })
            }));
            rows
        })
        .collect::<Vec<_>>();
    json!({
        "included": included,
        "noOp": no_op,
        "blocked": blocked,
        "reachExcluded": reach_excluded,
        "componentDiagnostics": component_diagnostics,
    })
}

pub(super) fn redacted_provider_coverage(
    coverage: &unpin_core::provider_reach::ProviderReachCoverage,
) -> Value {
    let mut summaries = BTreeMap::<ProviderId, (usize, usize, BTreeSet<String>)>::new();
    for entry in &coverage.entries {
        let summary = summaries.entry(entry.provider).or_default();
        if entry.included {
            summary.0 += 1;
        } else {
            summary.1 += 1;
        }
        if let Some(reason) = &entry.reason
            && let Ok(Value::String(reason)) = serde_json::to_value(reason)
        {
            summary.2.insert(reason);
        }
    }
    Value::Array(
        summaries
            .into_iter()
            .map(|(provider, (included, excluded, reason_codes))| {
                json!({
                    "provider": provider,
                    "included": included,
                    "excluded": excluded,
                    "reasonCodes": reason_codes,
                })
            })
            .collect(),
    )
}

pub(super) fn redacted_agent_plugin_apply(
    package: &AgentPluginSummary,
    result: &BulkToggleApplyResult,
) -> Value {
    let mut applied = 0;
    let mut no_op = 0;
    let mut blocked = 0;
    let mut recovery_required = 0;
    let mut backup_count = 0;
    let mut reason_codes = BTreeSet::new();
    for item in &result.items {
        match item.status {
            ToggleStatus::Applied => applied += 1,
            ToggleStatus::DryRun => no_op += 1,
            ToggleStatus::Blocked => blocked += 1,
            ToggleStatus::RecoveryRequired => recovery_required += 1,
        }
        backup_count += usize::from(item.backup_id.is_some());
        if let Some(reason) = &item.reason {
            reason_codes.insert(crate::commands::agent_plugins::safe_reason_code(reason));
        }
    }
    json!({
        "operationId": result.operation_id,
        "planFingerprint": result.plan_fingerprint,
        "lifecycle": result.lifecycle,
        "providerReach": result.provider_reach,
        "coverage": redacted_provider_coverage(&result.provider_coverage),
        "logicalId": package.logical_id,
        "name": package.name,
        "state": package.state,
        "access": package.access,
        "counts": {
            "applied": applied,
            "noOp": no_op,
            "blocked": blocked,
            "recoveryRequired": recovery_required,
            "backupCount": backup_count,
            "reasonCodes": reason_codes,
        },
    })
}
