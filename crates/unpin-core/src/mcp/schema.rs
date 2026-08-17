use super::*;

use serde_json::{Value, json};

pub(super) fn tool_descriptors(context: &McpContext) -> Vec<Value> {
    UNPIN_MCP_TOOL_NAMES
        .iter()
        .copied()
        .chain(
            context
                .approved_group_apply
                .as_ref()
                .map(|_| UNPIN_APPROVED_GROUP_APPLY_TOOL_NAME),
        )
        .map(|name| {
            json!({
                "name": name,
                "title": tool_title(name),
                "description": tool_description(name),
                "inputSchema": tool_input_schema(name, context.provider_scope),
                "annotations": tool_annotations(name)
            })
        })
        .collect()
}

pub(super) fn tool_title(name: &str) -> &'static str {
    match name {
        "unpin_get_inventory_summary" => "Get Unpin inventory summary",
        "unpin_list_items" => "List Unpin items",
        "unpin_list_agent_plugins" => "List Unpin Agent Plugin packages",
        "unpin_inspect_agent_plugin" => "Inspect one Unpin Agent Plugin package",
        "unpin_plan_agent_plugin_toggle" => "Plan one Unpin Agent Plugin package toggle",
        "unpin_list_inventory_groups" => "List Unpin inventory groups",
        "unpin_get_inventory_group" => "Get one Unpin inventory group",
        "unpin_plan_inventory_group" => "Plan one Unpin inventory group toggle",
        "unpin_apply_inventory_group" => "Apply one approved Unpin inventory group toggle",
        "unpin_plan_toggle_item" => "Plan one Unpin item toggle",
        "unpin_apply_toggle_item" => "Request one Unpin item toggle",
        "unpin_plan_toggle_items" => "Plan Unpin item toggles",
        "unpin_apply_toggle_items" => "Request Unpin item toggles",
        "unpin_list_backups" => "List Unpin backups",
        "unpin_restore_backup" => "Request Unpin backup restore",
        "unpin_run_doctor" => "Run Unpin doctor",
        "unpin_get_control_status" => "Get Unpin control status",
        "unpin_get_policy_maintenance_status" => "Get Unpin workspace policy maintenance status",
        "unpin_list_catalog" => "List Unpin catalog",
        "unpin_list_hooks" => "List Unpin hooks",
        "unpin_plan_catalog_adoption" => "Plan Unpin catalog adoption",
        "unpin_apply_catalog_adoption" => "Request Unpin catalog adoption",
        "unpin_plan_hook_trust" => "Plan Unpin hook trust",
        "unpin_apply_hook_trust" => "Request Unpin hook trust",
        "unpin_propose_session_profile" => "Propose Unpin session profile",
        "unpin_validate_profile" => "Validate Unpin profile",
        "unpin_list_workflows" => "List Unpin workflows",
        "unpin_validate_workflow" => "Validate Unpin workflow",
        "unpin_propose_session_workflow" => "Propose Unpin session workflow",
        "unpin_plan_workflow_session_launch" => "Plan Unpin workflow session launch",
        "unpin_plan_profile_policy" => "Plan Unpin profile policy",
        "unpin_apply_profile_policy" => "Request Unpin profile policy apply",
        "unpin_plan_profile_provider" => "Plan Unpin provider profile operation",
        "unpin_apply_profile_provider" => "Request Unpin provider profile apply",
        "unpin_get_capability_locks" => "Get Unpin capability locks",
        "unpin_plan_capability_lock" => "Plan Unpin capability lock",
        "unpin_apply_capability_lock" => "Request Unpin capability lock apply",
        "unpin_plan_gateway_mode" => "Plan Unpin gateway mode",
        "unpin_apply_gateway_mode" => "Request Unpin gateway mode apply",
        "unpin_get_gateway_status" => "Get Unpin gateway status",
        "unpin_plan_session_end" => "Plan Unpin session end",
        "unpin_apply_session_end" => "Request Unpin session end",
        "unpin_plan_session_launch" => "Plan isolated Unpin session launch",
        _ => "Unpin tool",
    }
}

pub(super) fn tool_description(name: &str) -> &'static str {
    match name {
        "unpin_get_inventory_summary" => {
            "Return structured provider inventory counts and discovery warnings."
        }
        "unpin_list_items" => {
            "List discovered Unpin provider items with optional selector filters."
        }
        "unpin_list_agent_plugins" => {
            "List path-free Agent Plugin package summaries derived from the scoped discovery cache without writing."
        }
        "unpin_inspect_agent_plugin" => {
            "Inspect path-free component dispositions, diagnostics, and native activation coverage for one derived Agent Plugin package without writing."
        }
        "unpin_plan_agent_plugin_toggle" => {
            "Refresh complete discovery, derive the package's exact native activation anchors internally, seal a durable reviewed handoff, and require human apply in Unpin CLI or desktop without mutating provider configuration."
        }
        "unpin_list_inventory_groups" => {
            "List visible named inventory groups and their current derived state without writing."
        }
        "unpin_get_inventory_group" => {
            "Inspect one qualified inventory group with fresh member state without writing."
        }
        "unpin_plan_inventory_group" => {
            "Plan enabling or disabling one exact inventory group without writing."
        }
        "unpin_apply_inventory_group" => {
            "Apply only the exact inventory group plan authorized by an external one-time human approval artifact."
        }
        "unpin_plan_toggle_item" => {
            "Plan a reversible toggle for one selected provider item without writing."
        }
        "unpin_apply_toggle_item" => {
            "Validate one exact toggle plan, persist transaction/payload metadata and coordination locks in Unpin app state, and return a human-action handoff without mutating provider configuration."
        }
        "unpin_plan_toggle_items" => {
            "Plan a bulk selector toggle and return a stable review fingerprint."
        }
        "unpin_apply_toggle_items" => {
            "Validate a reviewed bulk toggle plan, persist transaction/payload metadata and coordination locks in Unpin app state, and return a human-action handoff without mutating provider configuration."
        }
        "unpin_list_backups" => "List recent Unpin mutation backups from local app state.",
        "unpin_restore_backup" => {
            "Validate one backup restore request and return a human-action handoff without writing."
        }
        "unpin_run_doctor" => "Return structured fixture and provider discovery health output.",
        "unpin_get_control_status" => {
            "Return redacted catalog, profiles, policies, gateway, sessions, and hook coverage state."
        }
        "unpin_get_policy_maintenance_status" => {
            "Return authenticated workspace-policy binding and orphan classification with exact CLI handoffs; never mutate policy state."
        }
        "unpin_list_catalog" => {
            "List normalized catalog capabilities and provider contribution fan-out."
        }
        "unpin_list_hooks" => {
            "List granular hook metadata and optional profile-bound stored trust status without executable bodies or trust receipts."
        }
        "unpin_plan_catalog_adoption" => {
            "Plan copying one adoptable native skill or agent into Unpin catalog storage without writing."
        }
        "unpin_apply_catalog_adoption" => {
            "Validate an exact catalog adoption fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_hook_trust" => {
            "Plan profile-bound trust for one discovered hook without storing a receipt."
        }
        "unpin_apply_hook_trust" => {
            "Validate an exact hook-trust fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_propose_session_profile" => {
            "Rank locally stored profiles from metadata, return only a prompt digest, and require explicit user confirmation before session launch."
        }
        "unpin_validate_profile" => {
            "Validate one stored or inline typed profile against current catalog without materializing state."
        }
        "unpin_list_workflows" => {
            "List effective stored workflow metadata with workspace-over-global precedence without exposing paths or writing state."
        }
        "unpin_validate_workflow" => {
            "Compile one stored workflow against stored profiles, current catalog, and capability locks without accepting inline definitions or materializing a revision."
        }
        "unpin_propose_session_workflow" => {
            "Rank stored workflows with the shared CLI scoring contract, return only the prompt digest, and require explicit human confirmation without materializing or launching a session."
        }
        "unpin_plan_workflow_session_launch" => {
            "Recompile one stored workflow and return a human CLI/desktop materialization handoff without accepting paths or child commands, spawning a process, writing state, minting approval, or exposing session authority."
        }
        "unpin_plan_profile_policy" => {
            "Compile one stored profile and plan its next-session native/gateway policy selection without writing."
        }
        "unpin_apply_profile_policy" => {
            "Validate an exact profile policy fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_profile_provider" => {
            "Plan a named compiled profile for the explicitly reviewed provider reach, persist transaction/payload metadata and coordination locks in Unpin app state, and return it without mutating provider configuration."
        }
        "unpin_apply_profile_provider" => {
            "Validate an exact provider-profile reach fingerprint and return a schema-v2 CLI human-approval handoff without writing."
        }
        "unpin_get_capability_locks" => {
            "Return global provider capability lock revisions and conservative enforcement evidence without writing."
        }
        "unpin_plan_capability_lock" => {
            "Plan one global provider hard-enabled, hard-disabled, or cleared capability lock without writing."
        }
        "unpin_apply_capability_lock" => {
            "Validate an exact capability lock fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_gateway_mode" => {
            "Plan combined gateway lifecycle and profile policy changes without writing."
        }
        "unpin_apply_gateway_mode" => {
            "Validate an exact gateway workflow fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_get_gateway_status" => {
            "Return gateway mode and policy state for global, repository, or workspace scope without writing."
        }
        "unpin_plan_session_end" => {
            "Plan fencing one session while preserving process-owned cleanup state."
        }
        "unpin_apply_session_end" => {
            "Validate an exact session-end fingerprint and return a CLI human-approval handoff without writing."
        }
        "unpin_plan_session_launch" => {
            "Validate immutable session exposure identifiers and return an argv-safe CLI launch handoff without accepting a child command, spawning a process, writing state, minting approval, or exposing session authority."
        }
        _ => "Unpin MCP tool.",
    }
}

pub(super) fn tool_input_schema(name: &str, provider_scope: McpProviderScope) -> Value {
    let provider_ids = provider_scope.provider().map_or_else(
        || ProviderId::ALL.map(ProviderId::as_str).to_vec(),
        |provider| vec![provider.as_str()],
    );
    let mut schema = match name {
        "unpin_get_inventory_summary" => json!({
            "type": "object",
            "properties": {
                "providers": { "type": "array", "items": string_enum(&provider_ids) },
                "layers": { "type": "array", "items": string_enum(&["global", "project"]) }
            }
        }),
        "unpin_list_items" => json!({
            "type": "object",
            "properties": {
                "selector": selector_schema(&provider_ids),
                "limit": { "type": "integer", "minimum": 1 }
            }
        }),
        "unpin_list_agent_plugins" => json!({
            "type": "object",
            "required": [],
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_inspect_agent_plugin" => json!({
            "type": "object",
            "required": ["logicalId"],
            "properties": {
                "logicalId": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_agent_plugin_toggle" => json!({
            "type": "object",
            "required": ["logicalId", "targetEnabled", "providerReach"],
            "properties": {
                "logicalId": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                "providerReach": agent_plugin_provider_reach_schema(
                    &provider_ids,
                    provider_scope.provider().is_none(),
                )
            },
            "additionalProperties": false
        }),
        "unpin_list_inventory_groups" => json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_get_inventory_group" => json!({
            "type": "object",
            "required": ["group"],
            "properties": {
                "group": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_inventory_group" => json!({
            "type": "object",
            "required": ["group", "targetEnabled", "maxMembers", "providerReach"],
            "properties": {
                "group": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                "maxMembers": { "type": "integer", "minimum": 1, "maximum": 256 },
                "providerReach": {
                    "oneOf": [
                        { "type": "string", "enum": ["all", "all-providers", "omitted"] },
                        {
                            "type": "object",
                            "required": ["mode", "provider"],
                            "properties": {
                                "mode": { "type": "string", "enum": ["selected", "selected-provider"] },
                                "provider": non_empty_string_schema(),
                                "provenance": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    ]
                }
            },
            "additionalProperties": false
        }),
        "unpin_apply_inventory_group" => json!({
            "type": "object",
            "required": [
                "operationId",
                "planFingerprint",
                "challenge",
                "approvalArtifact"
            ],
            "properties": {
                "operationId": non_empty_string_schema(),
                "planFingerprint": non_empty_string_schema(),
                "challenge": non_empty_string_schema(),
                "approvalArtifact": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_toggle_item" => json!({
            "type": "object",
            "required": ["kind", "layer", "id", "targetEnabled"],
            "properties": {
                "provider": string_enum(&provider_ids),
                "kind": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]),
                "layer": string_enum(&["global", "project"]),
                "id": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" }
            }
        }),
        "unpin_apply_toggle_item" => json!({
            "type": "object",
            "required": ["kind", "layer", "id", "targetEnabled", "planFingerprint"],
            "properties": {
                "provider": string_enum(&provider_ids),
                "kind": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]),
                "layer": string_enum(&["global", "project"]),
                "id": non_empty_string_schema(),
                "targetEnabled": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "requireConfirmation": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "planFingerprint": non_empty_string_schema()
            }
        }),
        "unpin_plan_toggle_items" => json!({
            "type": "object",
            "required": ["targetEnabled"],
            "properties": {
                "selector": selector_schema(&provider_ids),
                "targetEnabled": { "type": "boolean" },
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" },
                "planFingerprint": { "type": "string" },
                "maxItems": { "type": "integer", "minimum": 0 },
                "allowEmptySelection": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "acknowledgeWholeInventory": { "type": "boolean" }
            },
            "additionalProperties": false
        }),
        "unpin_apply_toggle_items" => json!({
            "type": "object",
            "required": ["targetEnabled", "planFingerprint", "maxItems"],
            "properties": {
                "selector": selector_schema(&provider_ids),
                "targetEnabled": { "type": "boolean" },
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean" },
                "planFingerprint": { "type": "string" },
                "maxItems": { "type": "integer", "minimum": 0 },
                "allowEmptySelection": { "type": "boolean" },
                    "providerReach": provider_reach_input_schema(
                        &provider_ids,
                        provider_scope.provider().is_none(),
                    ),
                "acknowledgeWholeInventory": { "type": "boolean" }
            },
            "additionalProperties": false
        }),
        "unpin_restore_backup" => json!({
            "type": "object",
            "required": ["backupId"],
            "properties": {
                "backupId": non_empty_string_schema(),
                "requireConfirmation": { "type": "boolean" },
                "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
                "planFingerprint": non_empty_string_schema()
            }
        }),
        "unpin_list_backups" => json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "minimum": 1 }
            }
        }),
        "unpin_get_control_status" => json!({
            "type": "object",
            "properties": {
                "operationId": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_get_policy_maintenance_status" => json!({
            "type": "object",
            "properties": {
                "repositoryKey": non_empty_string_schema(),
                "workspaceKey": non_empty_string_schema(),
                "candidateCurrent": { "type": "boolean" }
            },
            "dependentRequired": {
                "repositoryKey": ["workspaceKey"],
                "workspaceKey": ["repositoryKey"]
            },
            "additionalProperties": false
        }),
        "unpin_list_catalog" => json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_list_hooks" => json!({
            "type": "object",
            "properties": {
                "provider": string_enum(&provider_ids),
                "profileDigest": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_propose_session_profile" => json!({
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": { "type": "string", "minLength": 1, "maxLength": 16384 },
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_validate_profile" => json!({
            "type": "object",
            "properties": {
                "profileId": non_empty_string_schema(),
                "definition": { "type": "object" },
                "sourceScope": string_enum(&["global", "repository", "workspace", "session"])
            },
            "oneOf": [
                { "required": ["profileId"] },
                { "required": ["definition", "sourceScope"] }
            ],
            "additionalProperties": false
        }),
        "unpin_list_workflows" => json!({
            "type": "object",
            "required": [],
            "properties": {},
            "additionalProperties": false
        }),
        "unpin_validate_workflow" => json!({
            "type": "object",
            "required": ["workflowId"],
            "properties": {
                "workflowId": non_empty_string_schema(),
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_propose_session_workflow" => json!({
            "type": "object",
            "required": ["prompt"],
            "properties": {
                "prompt": { "type": "string", "minLength": 1, "maxLength": 16384 },
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_plan_workflow_session_launch" => json!({
            "type": "object",
            "required": ["workflowId", "provider"],
            "properties": {
                "workflowId": non_empty_string_schema(),
                "provider": string_enum(&provider_ids),
                "workflowRevision": non_empty_string_schema(),
                "promptDigest": non_empty_string_schema()
            },
            "additionalProperties": false
        }),
        "unpin_plan_catalog_adoption" => control_catalog_adoption_schema(&provider_ids, false),
        "unpin_apply_catalog_adoption" => control_catalog_adoption_schema(&provider_ids, true),
        "unpin_plan_hook_trust" => control_hook_trust_schema(&provider_ids, false),
        "unpin_apply_hook_trust" => control_hook_trust_schema(&provider_ids, true),
        "unpin_plan_profile_policy" => control_profile_schema(&provider_ids, false),
        "unpin_apply_profile_policy" => control_profile_schema(&provider_ids, true),
        "unpin_plan_profile_provider" => control_profile_provider_schema(&provider_ids, false),
        "unpin_apply_profile_provider" => control_profile_provider_schema(&provider_ids, true),
        "unpin_get_capability_locks" => json!({
            "type": "object",
            "properties": {
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_plan_capability_lock" => control_capability_lock_schema(&provider_ids, false),
        "unpin_apply_capability_lock" => control_capability_lock_schema(&provider_ids, true),
        "unpin_plan_gateway_mode" => control_gateway_schema(&provider_ids, false),
        "unpin_apply_gateway_mode" => control_gateway_schema(&provider_ids, true),
        "unpin_get_gateway_status" => json!({
            "type": "object",
            "properties": {
                "scope": string_enum(&["global", "repository", "workspace"]),
                "provider": string_enum(&provider_ids)
            },
            "additionalProperties": false
        }),
        "unpin_plan_session_end" => control_session_end_schema(false),
        "unpin_apply_session_end" => control_session_end_schema(true),
        "unpin_plan_session_launch" => control_session_launch_schema(&provider_ids),
        _ => json!({
            "type": "object",
            "properties": {}
        }),
    };
    if provider_scope.provider().is_some() {
        remove_provider_requirement(&mut schema);
    }
    schema
}

pub(super) fn remove_provider_requirement(schema: &mut Value) {
    match schema {
        Value::Array(values) => {
            for value in values {
                remove_provider_requirement(value);
            }
        }
        Value::Object(object) => {
            if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
                required.retain(|field| field.as_str() != Some("provider"));
            }
            for value in object.values_mut() {
                remove_provider_requirement(value);
            }
        }
        _ => {}
    }
}

pub(super) fn control_catalog_adoption_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("id"), json!("providerRoot")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "id": non_empty_string_schema(),
            "providerRoot": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_hook_trust_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("id"), json!("profileDigest")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "id": non_empty_string_schema(),
            "profileDigest": non_empty_string_schema(),
            "sessionId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_profile_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("profileId"), json!("mode")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "profileId": non_empty_string_schema(),
            "mode": string_enum(&["native", "gateway"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_profile_provider_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("profileId"), json!("mode"), json!("providerReach")];
    if apply {
        required.push(json!("operationId"));
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "profileId": non_empty_string_schema(),
            "mode": string_enum(&["native", "gateway"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "providerReach": {
                "oneOf": [
                    { "type": "string", "enum": ["all", "all-providers", "omitted"] },
                    {
                        "type": "object",
                        "required": ["mode", "provider"],
                        "properties": {
                            "mode": { "type": "string", "enum": ["selected", "selected-provider"] },
                            "provider": string_enum(provider_ids),
                            "provenance": { "type": "string" }
                        },
                        "additionalProperties": false
                    }
                ]
            },
            "operationId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_capability_lock_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("provider"), json!("capabilityId"), json!("state")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "provider": string_enum(provider_ids),
            "capabilityId": non_empty_string_schema(),
            "state": string_enum(&["hard-enabled", "hard-disabled", "clear"]),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_gateway_schema(provider_ids: &[&str], apply: bool) -> Value {
    let mut required = vec![json!("action")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "action": string_enum(&["install", "on", "off", "detach"]),
            "scope": string_enum(&["global", "repository", "workspace"]),
            "provider": string_enum(provider_ids),
            "force": { "type": "boolean" },
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_session_end_schema(apply: bool) -> Value {
    let mut required = vec![json!("sessionId")];
    if apply {
        required.push(json!("planFingerprint"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": {
            "sessionId": non_empty_string_schema(),
            "confirm": { "type": "boolean", "description": "Compatibility field only; never authorizes MCP mutation." },
            "planFingerprint": non_empty_string_schema()
        },
        "additionalProperties": false
    })
}

pub(super) fn control_session_launch_schema(provider_ids: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": ["provider", "exposureRevision", "profile"],
        "properties": {
            "provider": string_enum(provider_ids),
            "exposureRevision": non_empty_string_schema(),
            "profile": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": string_enum(&["native"])
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": string_enum(&["none"])
                        },
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["type", "profileId", "profileDigest", "definitionDigest"],
                        "properties": {
                            "type": string_enum(&["profile"]),
                            "profileId": non_empty_string_schema(),
                            "profileDigest": non_empty_string_schema(),
                            "definitionDigest": non_empty_string_schema()
                        },
                        "additionalProperties": false
                    }
                ]
            }
        },
        "additionalProperties": false
    })
}

pub(super) fn tool_annotations(name: &str) -> Value {
    match name {
        "unpin_apply_inventory_group" => json!({
            "readOnlyHint": false,
            "destructiveHint": true,
            "idempotentHint": false
        }),
        "unpin_apply_toggle_item"
        | "unpin_apply_toggle_items"
        | "unpin_plan_agent_plugin_toggle"
        | "unpin_plan_profile_provider" => {
            json!({
                "readOnlyHint": false,
                "destructiveHint": false
            })
        }
        "unpin_get_inventory_summary"
        | "unpin_list_items"
        | "unpin_list_agent_plugins"
        | "unpin_inspect_agent_plugin"
        | "unpin_list_inventory_groups"
        | "unpin_get_inventory_group"
        | "unpin_plan_inventory_group"
        | "unpin_plan_toggle_item"
        | "unpin_plan_toggle_items"
        | "unpin_list_backups"
        | "unpin_restore_backup"
        | "unpin_run_doctor"
        | "unpin_get_control_status"
        | "unpin_get_policy_maintenance_status"
        | "unpin_list_catalog"
        | "unpin_list_hooks"
        | "unpin_plan_catalog_adoption"
        | "unpin_apply_catalog_adoption"
        | "unpin_plan_hook_trust"
        | "unpin_apply_hook_trust"
        | "unpin_propose_session_profile"
        | "unpin_validate_profile"
        | "unpin_list_workflows"
        | "unpin_validate_workflow"
        | "unpin_propose_session_workflow"
        | "unpin_plan_workflow_session_launch"
        | "unpin_plan_profile_policy"
        | "unpin_apply_profile_policy"
        | "unpin_apply_profile_provider"
        | "unpin_get_capability_locks"
        | "unpin_plan_capability_lock"
        | "unpin_apply_capability_lock"
        | "unpin_plan_gateway_mode"
        | "unpin_apply_gateway_mode"
        | "unpin_get_gateway_status"
        | "unpin_plan_session_end"
        | "unpin_apply_session_end"
        | "unpin_plan_session_launch" => json!({
            "readOnlyHint": true
        }),
        _ => json!({}),
    }
}

pub(super) fn selector_schema(provider_ids: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": {
            "providers": { "type": "array", "items": string_enum(provider_ids) },
            "kinds": { "type": "array", "items": string_enum(&["skill", "mcp", "plugin", "agent", "hook", "setting"]) },
            "categories": { "type": "array", "items": string_enum(&[
                "skill",
                "configured-mcp",
                "tool",
                "agent",
                "hook",
                "provider-setting",
                "plugin-config",
                "plugin-manifest"
            ]) },
            "layers": { "type": "array", "items": string_enum(&["global", "project"]) },
            "enabled": { "type": "boolean" },
            "ids": { "type": "array", "items": non_empty_string_schema() }
        },
        "additionalProperties": false
    })
}

pub(super) fn string_enum(values: &[&str]) -> Value {
    json!({
        "type": "string",
        "enum": values
    })
}

pub(super) fn provider_reach_input_schema(
    provider_ids: &[&str],
    selected_provider_required: bool,
) -> Value {
    provider_reach_schema(provider_ids, selected_provider_required, true)
}

pub(super) fn agent_plugin_provider_reach_schema(
    provider_ids: &[&str],
    selected_provider_required: bool,
) -> Value {
    provider_reach_schema(provider_ids, selected_provider_required, false)
}

pub(super) fn provider_reach_schema(
    provider_ids: &[&str],
    selected_provider_required: bool,
    allow_omitted: bool,
) -> Value {
    let mut selected_required = vec![json!("mode")];
    if selected_provider_required {
        selected_required.push(json!("provider"));
    }
    let mut string_modes = vec!["all", "all-providers"];
    if allow_omitted {
        string_modes.push("omitted");
    }
    json!({
        "oneOf": [
            {
                "type": "string",
                "enum": string_modes
            },
            {
                "type": "object",
                "required": ["mode"],
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["all", "all-providers"]
                    }
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": selected_required,
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["selected", "selected-provider"]
                    },
                    "provider": {
                        "type": "string",
                        "enum": provider_ids
                    }
                },
                "additionalProperties": false
            }
        ]
    })
}

pub(super) fn non_empty_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1
    })
}
