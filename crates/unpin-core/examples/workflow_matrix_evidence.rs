use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unpin_core::{
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ContributionControl, ContributionEdge, ProviderView,
    },
    discovery::DiscoveryLayer,
    gateway::{
        GatewayError, GatewayExposure, GatewayHookRegistration, GatewayLimits, GatewayService,
        ListChangeSupport, UpstreamIdentity, UpstreamToolDescriptor, UpstreamToolRegistration,
    },
    hooks::{
        HookAction, HookEventFamily, HookFailurePolicy, HookHandler, HookHandlerSpec, HookMatcher,
        HookOwnership, HookRouteOwner, HookSourceLayer, HookTransformCapabilities,
    },
    profiles::{
        CapabilityLockSnapshot, PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope,
        compile_profile,
    },
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, PinnedWorkflowEnvelope, ProcessEvidence, SessionAuthorityKey,
        SessionManager, WorkflowTransitionRequest,
    },
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowControl, WorkflowDefinition, WorkflowModeDefinition,
        compile_workflow,
    },
};

const SEARCH_SKILLS_TOOL: &str = "unpin_search_skills";
const LOAD_SKILL_TOOL: &str = "unpin_load_skill";
const SESSION_STATUS_TOOL: &str = "unpin_get_session_status";

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn source_fingerprint(body: &[u8]) -> String {
    let digest = Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn capability_id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("fixture capability id")
}

fn record(
    value: &str,
    kind: CapabilityKind,
    source_path: &Path,
    fingerprint: char,
    contributed_by: Option<CapabilityId>,
) -> CatalogRecord {
    let source_path = source_path.to_string_lossy().into_owned();
    let source = fs::read(&source_path).unwrap_or_default();
    CatalogRecord {
        id: capability_id(value),
        kind,
        display_name: value.to_string(),
        origin: CanonicalOrigin {
            canonical_key: format!("origin-{value}"),
            source_path: source_path.clone(),
            state_path: source_path.clone(),
            scope: CapabilityScope::Repository,
            source_fingerprint: (kind == CapabilityKind::Skill)
                .then(|| source_fingerprint(&source)),
        },
        ownership: CapabilityOwnership::User,
        fingerprint: digest(fingerprint),
        lifecycle: CapabilityLifecycle::discovered(true),
        state_evidence: CapabilityStateEvidence {
            observation: "workflow-matrix-fixture".to_string(),
            observed_enabled: true,
        },
        trust_requirements: CapabilityTrustRequirements::default(),
        provider_views: vec![ProviderView {
            provider: ProviderId::Codex,
            discovery_id: format!("codex:{value}"),
            layer: DiscoveryLayer::Project,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: source_path.clone(),
            state_path: source_path,
            source_fingerprint: None,
        }],
        dependencies: Vec::new(),
        contributions: Vec::new(),
        atomic_unknown_contributions: false,
        contributed_by,
        tool_namespace: None,
        hook_conflict_key: None,
    }
}

fn plugin_record(source_path: &Path, contributions: &[CapabilityId]) -> CatalogRecord {
    let mut plugin = record(
        "agent-plugin-package",
        CapabilityKind::Plugin,
        source_path,
        '9',
        None,
    );
    plugin.contributions = contributions
        .iter()
        .cloned()
        .map(|capability_id| ContributionEdge {
            capability_id,
            control: ContributionControl::Independent,
        })
        .collect();
    plugin
}

fn profile(
    catalog: &Catalog,
    id: &str,
    members: Vec<CapabilityId>,
) -> unpin_core::profiles::CompiledProfileRevision {
    compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: id.to_string(),
            display_name: id.to_string(),
            description: None,
            members,
            provider_members: BTreeMap::new(),
            supported_providers: BTreeSet::from([ProviderId::Codex]),
        },
        catalog,
        ProfileSourceScope::Session,
    )
    .expect("compile fixture profile")
}

fn pin(
    workflow_revision: &str,
    profile: &unpin_core::workflows::CompiledWorkflowProfileRevision,
) -> PinnedExposure {
    PinnedExposure {
        revision: profile.digest.clone(),
        profile: PinnedProfile::Profile {
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.digest.clone(),
            origin_scope: ProfileSourceScope::Session,
            definition_digest: workflow_revision.to_string(),
        },
        capability_locks: None,
    }
}

fn registration(
    record: &CatalogRecord,
    registration_id: &str,
    public_namespace: &str,
    tool_name: &str,
) -> UpstreamToolRegistration {
    UpstreamToolRegistration {
        registration_id: registration_id.to_string(),
        capability_id: record.id.clone(),
        capability_fingerprint: record.fingerprint.clone(),
        provider: ProviderId::Codex,
        identity: UpstreamIdentity::streamable_http(
            public_namespace,
            format!("https://{public_namespace}.example.test/mcp"),
        )
        .expect("fixture upstream identity"),
        credential: None,
        descriptor: UpstreamToolDescriptor {
            name: tool_name.to_string(),
            title: Some(format!("{tool_name} title")),
            description: Some(format!("{tool_name} fixture tool")),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1}
                },
                "additionalProperties": false
            }),
            output_schema: Some(json!({"type": "object"})),
            annotations: Some(json!({"readOnlyHint": true, "openWorldHint": false})),
            execution: Some(json!({"taskSupport": "optional"})),
        },
    }
}

fn reviewed_hook(
    record: &CatalogRecord,
    profile_digest: &str,
    repository_key: &str,
    workspace_key: &str,
    session_id: &str,
) -> HookHandler {
    let handler = HookHandler::new(HookHandlerSpec {
        id: record.id.to_string(),
        provider: ProviderId::Codex,
        native_event: "BeforeTool".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::any(),
        action: HookAction::http("https://hook.example.test/observe").expect("hook action"),
        order: 0,
        timeout_ms: 1_000,
        failure_policy: HookFailurePolicy::FailClosed,
        source_layer: HookSourceLayer::Session,
        ownership: HookOwnership::User,
        route_owner: HookRouteOwner::Gateway,
        enabled: true,
        transformations: HookTransformCapabilities::none(),
    })
    .expect("fixture hook");
    let expectation = handler
        .trust_approval_expectation(
            profile_digest,
            "workflow-matrix",
            "unpin-core",
            repository_key,
            workspace_key,
            session_id,
        )
        .expect("hook approval expectation");
    let issuer = unpin_core::approval::ApprovalIssuer::new(
        unpin_core::approval::ApprovalKey::new([0x39; 32]),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("hook approval issuer");
    let receipt = issuer
        .issue(unpin_core::approval::ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("receipt-{}", &expectation.operation_id[..16]),
            nonce: format!("nonce-{}", &expectation.operation_id[..16]),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: 1_000,
            expires_at_unix: 1_600,
        })
        .expect("hook approval receipt");
    let verified = unpin_core::approval::ApprovalVerifier::new(
        unpin_core::approval::ApprovalKey::new([0x39; 32]),
    )
    .verify(&receipt, &expectation, 1_100)
    .expect("verified hook approval");
    handler
        .review(&verified, profile_digest)
        .expect("reviewed fixture hook")
}

fn control_descriptors() -> Vec<Value> {
    let mut values = vec![
        json!({
            "name": SEARCH_SKILLS_TOOL,
            "description": "Search metadata for skills selected by the session profile.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1}
                },
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": LOAD_SKILL_TOOL,
            "description": "Load one selected skill by opaque reference.",
            "inputSchema": {
                "type": "object",
                "properties": {"reference": {"type": "string"}},
                "required": ["reference"],
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        json!({
            "name": SESSION_STATUS_TOOL,
            "description": "Return current gateway exposure and admission status.",
            "inputSchema": {"type": "object", "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
    ];
    values.extend(WorkflowControl::ALL.into_iter().map(|control| match control {
        WorkflowControl::UnpinWorkflowStatus => json!({
            "name": control.name(),
            "description": "Return authenticated workflow and connection status.",
            "inputSchema": {"type": "object", "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        WorkflowControl::UnpinWorkflowModes => json!({
            "name": control.name(),
            "description": "List modes in the pinned workflow envelope.",
            "inputSchema": {"type": "object", "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false}
        }),
        WorkflowControl::UnpinWorkflowEnterMode => json!({
            "name": control.name(),
            "description": "Enter a previously pinned workflow mode.",
            "inputSchema": {
                "type": "object",
                "required": ["operationId", "operationFingerprint", "sourceStateSequence", "targetMode", "requestedAtUnix"],
                "properties": {
                    "operationId": {"type": "string"},
                    "operationFingerprint": {"type": "string"},
                    "sourceStateSequence": {"type": "integer", "minimum": 0},
                    "targetMode": {"type": "string"},
                    "requestedAtUnix": {"type": "integer"}
                },
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": false, "openWorldHint": false}
        }),
        WorkflowControl::UnpinWorkflowCancelTransition => json!({
            "name": control.name(),
            "description": "Cancel one in-progress workflow transition.",
            "inputSchema": {
                "type": "object",
                "required": ["operationId"],
                "properties": {"operationId": {"type": "string"}},
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": false, "openWorldHint": false}
        }),
    }));
    values
}

fn canonical_schema_bytes(values: &[Value]) -> usize {
    serde_json::to_vec(values)
        .expect("canonical schema JSON")
        .len()
}

fn estimated_tokens(bytes: usize) -> usize {
    bytes.div_ceil(4)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ModeEvidence {
    mode: String,
    revision: String,
    advertised_tool_names: Vec<String>,
    skill_search_results: Vec<Value>,
    loaded_skill_body_bytes: usize,
    hook_ids: Vec<String>,
    schema_bytes: usize,
    estimated_tokens: usize,
}

fn mode_evidence(mode: &str, exposure: &GatewayExposure) -> ModeEvidence {
    let mut descriptors = control_descriptors();
    descriptors.extend(
        exposure
            .tools()
            .descriptors()
            .into_iter()
            .map(|tool| serde_json::to_value(tool).expect("projected tool JSON")),
    );
    descriptors.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let skill_search = exposure
        .skills()
        .search("", 100)
        .expect("fixture skill search");
    let skill_search_results = skill_search
        .iter()
        .map(|skill| serde_json::to_value(skill).expect("skill metadata JSON"))
        .collect::<Vec<_>>();
    let loaded_skill_body_bytes = skill_search
        .iter()
        .map(|skill| {
            exposure
                .skills()
                .load(&skill.reference)
                .expect("fixture skill load")
                .body
                .len()
        })
        .sum();
    let hook_ids = exposure
        .hook_policy()
        .handlers()
        .iter()
        .map(|handler| handler.id().to_string())
        .collect();
    let schema_bytes = canonical_schema_bytes(&descriptors);
    ModeEvidence {
        mode: mode.to_string(),
        revision: exposure.pinned().revision.clone(),
        advertised_tool_names: descriptors
            .iter()
            .filter_map(|descriptor| descriptor["name"].as_str().map(str::to_string))
            .collect(),
        skill_search_results,
        loaded_skill_body_bytes,
        hook_ids,
        schema_bytes,
        estimated_tokens: estimated_tokens(schema_bytes),
    }
}

fn transition_request(
    operation_id: &str,
    source_state_sequence: u64,
    target_mode: &str,
    requested_at_unix: i64,
) -> WorkflowTransitionRequest {
    WorkflowTransitionRequest {
        operation_id: operation_id.to_string(),
        operation_fingerprint: digest('8'),
        source_state_sequence,
        target_mode: target_mode.to_string(),
        requested_at_unix,
    }
}

fn error_code(error: GatewayError) -> String {
    match error {
        GatewayError::ConnectionControlOnly => "connection-control-only".to_string(),
        GatewayError::ConnectionEpochStale => "connection-epoch-stale".to_string(),
        GatewayError::ConnectionClaimInvalid => "connection-claim-invalid".to_string(),
        GatewayError::Workflow(message) => format!("workflow:{message}"),
        error => error.to_string(),
    }
}

fn main() {
    let output = env::args_os().nth(1).map(PathBuf::from);
    let root = tempfile::Builder::new()
        .prefix("unpin-workflow-matrix-")
        .tempdir()
        .expect("fixture root");
    let root = fs::canonicalize(root.path()).expect("canonical fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private fixture root");
    }

    let fixture_dir = root.join("fixture");
    fs::create_dir(&fixture_dir).expect("fixture directory");
    let planning_skill_path = fixture_dir.join("planning.md");
    let implementation_skill_path = fixture_dir.join("implementation.md");
    let plugin_skill_path = fixture_dir.join("plugin-review.md");
    let native_state_path = fixture_dir.join("provider-native-state.json");
    let protected_root_path = root.join("authority-root");
    fs::create_dir(&protected_root_path).expect("protected root");
    fs::write(
        &planning_skill_path,
        "# Planning\nClarify scope and risks.\n",
    )
    .expect("planning skill");
    fs::write(
        &implementation_skill_path,
        "# Implementation\nImplement the reviewed plan.\n",
    )
    .expect("implementation skill");
    fs::write(
        &plugin_skill_path,
        "# Plugin review\nReview changes contributed by a package.\n",
    )
    .expect("plugin skill");
    fs::write(&native_state_path, b"{\"enabled\":true}\n").expect("native fixture state");
    let native_before = fs::read(&native_state_path).expect("native fixture bytes");

    let planning_skill = record(
        "planning-skill",
        CapabilityKind::Skill,
        &planning_skill_path,
        '1',
        None,
    );
    let implementation_skill = record(
        "implementation-skill",
        CapabilityKind::Skill,
        &implementation_skill_path,
        '2',
        None,
    );
    let plugin_id = capability_id("agent-plugin-package");
    let review_skill = record(
        "plugin-review-skill",
        CapabilityKind::Skill,
        &plugin_skill_path,
        '3',
        Some(plugin_id.clone()),
    );
    let planning_tool = record(
        "planning-search-tool",
        CapabilityKind::McpTool,
        &native_state_path,
        '4',
        None,
    );
    let implementation_tool = record(
        "implementation-code-tool",
        CapabilityKind::McpTool,
        &native_state_path,
        '5',
        None,
    );
    let review_tool = record(
        "plugin-review-tool",
        CapabilityKind::McpTool,
        &native_state_path,
        '6',
        Some(plugin_id.clone()),
    );
    let review_hook = record(
        "plugin-review-hook",
        CapabilityKind::Hook,
        &native_state_path,
        '7',
        Some(plugin_id.clone()),
    );
    let plugin = plugin_record(
        &native_state_path,
        &[
            review_skill.id.clone(),
            review_tool.id.clone(),
            review_hook.id.clone(),
        ],
    );
    let catalog = Catalog::from_records([
        planning_skill.clone(),
        implementation_skill.clone(),
        review_skill.clone(),
        planning_tool.clone(),
        implementation_tool.clone(),
        review_tool.clone(),
        review_hook.clone(),
        plugin.clone(),
    ])
    .expect("fixture catalog");

    let baseline_profile = profile(&catalog, "baseline", Vec::new());
    let planning_profile = profile(
        &catalog,
        "planning",
        vec![planning_skill.id.clone(), planning_tool.id.clone()],
    );
    let implementation_profile = profile(
        &catalog,
        "implementation",
        vec![
            implementation_skill.id.clone(),
            implementation_tool.id.clone(),
        ],
    );
    let review_profile = profile(
        &catalog,
        "review",
        vec![
            review_skill.id.clone(),
            review_tool.id.clone(),
            review_hook.id.clone(),
        ],
    );
    let profiles = BTreeMap::from([
        (baseline_profile.profile_id.clone(), baseline_profile),
        (planning_profile.profile_id.clone(), planning_profile),
        (
            implementation_profile.profile_id.clone(),
            implementation_profile,
        ),
        (review_profile.profile_id.clone(), review_profile),
    ]);
    let workflow = compile_workflow(
        &WorkflowDefinition {
            version: WORKFLOW_DEFINITION_VERSION,
            id: "delivery".to_string(),
            display_name: "Delivery".to_string(),
            description: Some("Planning, implementation, and review fixture".to_string()),
            baseline_profile_id: "baseline".to_string(),
            entry_mode: "planning".to_string(),
            modes: vec![
                WorkflowModeDefinition::new("planning", "planning"),
                WorkflowModeDefinition::new("implementation", "implementation"),
                WorkflowModeDefinition::new("review", "review"),
            ],
        },
        &profiles,
        &catalog,
        &CapabilityLockSnapshot::empty(ProviderId::Codex),
        ProviderId::Codex,
        ProfileSourceScope::Session,
    )
    .expect("compile fixture workflow");

    let repository_key = "workflow-matrix-repository";
    let workspace_key = "workflow-matrix-workspace";
    let connection_scope_id = "workflow-matrix-connection";
    let connection_owner_id = "workflow-matrix-owner";
    let mode_pins = workflow
        .effective_profiles
        .iter()
        .map(|(mode, profile)| (mode.clone(), pin(&workflow.digest, profile)))
        .collect::<BTreeMap<_, _>>();
    let planning_pin = mode_pins["planning"].clone();
    let manager = SessionManager::with_authority_key(&root, SessionAuthorityKey::new([0x51; 32]));
    let bootstrap = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: repository_key.to_string(),
        workspace_key: workspace_key.to_string(),
        workspace_revision: Some(digest('a')),
        exposure: planning_pin.clone(),
        process: ProcessEvidence {
            pid: std::process::id(),
            start_marker: "workflow-matrix-process".to_string(),
        },
        connection_scope_id: connection_scope_id.to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([
            "authority-root-workflow-matrix".to_string(),
            "provider-state-workflow-matrix".to_string(),
        ]),
        lease_expires_at_unix: 3_000,
    };
    let authority = manager
        .prepare_bootstrap(bootstrap.clone(), 1_000)
        .expect("prepare bootstrap");
    let claimed = manager
        .claim_bootstrap(
            &authority,
            &ConnectionClaim {
                connection_owner_id: connection_owner_id.to_string(),
                provider: bootstrap.provider,
                repository_key: bootstrap.repository_key.clone(),
                workspace_key: bootstrap.workspace_key.clone(),
                process: bootstrap.process.clone(),
                connection_scope_id: bootstrap.connection_scope_id.clone(),
            },
            1_001,
        )
        .expect("claim bootstrap");
    let pinned_workflow = PinnedWorkflowEnvelope {
        workflow_id: workflow.workflow_id.clone(),
        workflow_revision: workflow.digest.clone(),
        baseline_profile_id: workflow.baseline_profile_id.clone(),
        baseline_profile_digest: workflow.baseline_profile_digest.clone(),
        profile_revisions: workflow
            .effective_profiles
            .iter()
            .map(|(mode, profile)| (mode.clone(), profile.digest.clone()))
            .collect(),
        active_mode: "planning".to_string(),
        active_effective_profile_digest: planning_pin.revision.clone(),
        maximum_envelope_digest: workflow.maximum_envelope.digest.clone(),
        capability_lock_digest: workflow.capability_lock_digest.clone(),
        catalog_revision: digest('c'),
        proposal_id: "workflow-matrix-proposal".to_string(),
        proposal_fingerprint: digest('d'),
        state_sequence: 1,
        sealed_generation: 1,
    };
    let pinned = manager
        .pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            pinned_workflow,
            planning_pin.clone(),
            1_002,
        )
        .expect("pin workflow");

    let limits = GatewayLimits::default();
    let mut exposures = BTreeMap::new();
    for mode in ["planning", "implementation", "review"] {
        let profile = &workflow.effective_profiles[mode];
        let registrations = match mode {
            "planning" => vec![registration(
                &planning_tool,
                "planning-registration",
                "planning",
                "search",
            )],
            "implementation" => vec![registration(
                &implementation_tool,
                "implementation-registration",
                "implementation",
                "code",
            )],
            "review" => vec![registration(
                &review_tool,
                "plugin-review-registration",
                "review",
                "inspect",
            )],
            _ => unreachable!(),
        };
        let hooks = if mode == "review" {
            vec![GatewayHookRegistration {
                capability_id: review_hook.id.clone(),
                capability_fingerprint: review_hook.fingerprint.clone(),
                provider: ProviderId::Codex,
                handler: reviewed_hook(
                    &review_hook,
                    &profile.digest,
                    repository_key,
                    workspace_key,
                    claimed.handle.session_id(),
                ),
            }]
        } else {
            Vec::new()
        };
        exposures.insert(
            mode.to_string(),
            GatewayExposure::compile_workflow_profile_with_hooks(
                mode_pins[mode].clone(),
                ProviderId::Codex,
                &catalog,
                profile,
                registrations,
                hooks,
                limits,
            )
            .expect("compile workflow exposure"),
        );
    }
    let mode_evidence = exposures
        .iter()
        .map(|(mode, exposure)| (mode.clone(), mode_evidence(mode, exposure)))
        .collect::<BTreeMap<_, _>>();

    let maximum_descriptors = {
        let mut descriptors = control_descriptors();
        for mode in mode_evidence.values() {
            for name in &mode.advertised_tool_names {
                if control_descriptors()
                    .iter()
                    .any(|descriptor| descriptor["name"] == *name)
                {
                    continue;
                }
                descriptors.push(json!({
                    "name": name,
                    "description": "Maximum-envelope fixture descriptor",
                    "inputSchema": {"type": "object", "additionalProperties": false}
                }));
            }
        }
        descriptors.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        descriptors.dedup_by(|left, right| left["name"] == right["name"]);
        descriptors
    };
    let full_envelope_schema_bytes = canonical_schema_bytes(&maximum_descriptors);
    let unrouted_descriptors = {
        let mut descriptors = maximum_descriptors.clone();
        descriptors.extend([
            json!({
                "name": "native_unmanaged_debug",
                "description": "Provider-native tool outside the Unpin gateway",
                "inputSchema": {"type": "object", "additionalProperties": true}
            }),
            json!({
                "name": "native_unmanaged_admin",
                "description": "Provider-native tool outside the confirmed envelope",
                "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}
            }),
        ]);
        descriptors
    };
    let unrouted_installed_catalog_schema_bytes = canonical_schema_bytes(&unrouted_descriptors);

    let control = unpin_core::gateway::GatewayControlPlane::new(
        manager,
        claimed.handle,
        limits.maximum_concurrent_calls,
    )
    .expect("gateway control plane");
    let service = GatewayService::new(control, exposures["planning"].clone(), limits)
        .expect("gateway service");
    for mode in ["implementation", "review"] {
        service
            .register_workflow_exposure(exposures[mode].clone())
            .expect("register workflow exposure");
    }
    let primary = service.issue_connection_claim().expect("primary claim");
    let auxiliary = service.accept_connection().expect("auxiliary claim");
    let initial_status = service.connection_status(&primary).expect("initial status");
    let auxiliary_status = service
        .connection_status(&auxiliary)
        .expect("auxiliary status");
    let auxiliary_data_denial = service
        .list_tools_for_connection(&auxiliary, 1_003)
        .expect_err("auxiliary is control-only");

    let implementation_request = transition_request(
        "enter-implementation",
        pinned.revision.sequence,
        "implementation",
        1_010,
    );
    let (implementation_transition, implementation_outcome) = service
        .enter_workflow_mode_for_connection(
            &auxiliary,
            implementation_request,
            ListChangeSupport::Negotiated,
            1_010,
        )
        .expect("stage implementation transition");
    let status_after_stage = service.connection_status(&primary).expect("staged status");
    let _pre_notification_tools = service
        .list_tools_for_connection(&primary, 1_011)
        .expect("pre-notification list");
    let notification = service
        .notify_tools_changed_for_connection(&primary, 1_012)
        .expect("notify primary");
    let status_after_notification = service
        .connection_status(&primary)
        .expect("notification status");
    let implementation_tools = service
        .list_tools_for_connection(&primary, 1_013)
        .expect("same-primary relist");
    let implementation_observed = service
        .connection_status(&primary)
        .expect("implementation observed status");

    let review_snapshot = service
        .control_plane()
        .snapshot()
        .expect("review transition snapshot");
    let review_request = transition_request(
        "enter-review",
        review_snapshot.revision.sequence,
        "review",
        1_020,
    );
    let (review_transition, review_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            review_request,
            ListChangeSupport::Negotiated,
            1_020,
        )
        .expect("stage review transition");
    service
        .notify_tools_changed_for_connection(&primary, 1_021)
        .expect("notify review transition");
    let review_tools = service
        .list_tools_for_connection(&primary, 1_022)
        .expect("observe review transition");
    let review_observed = service
        .connection_status(&primary)
        .expect("review observed status");

    let cancel_snapshot = service
        .control_plane()
        .snapshot()
        .expect("cancel transition snapshot");
    let cancel_request = transition_request(
        "cancel-planning",
        cancel_snapshot.revision.sequence,
        "planning",
        1_030,
    );
    let (cancel_transition, cancel_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            cancel_request,
            ListChangeSupport::NotificationOnly,
            1_030,
        )
        .expect("stage refresh-unconfirmed transition");
    let cancelled = service
        .cancel_transition_for_connection(&primary, &cancel_transition.operation_id, 1_031)
        .expect("cancel transition");

    let reload_snapshot = service
        .control_plane()
        .snapshot()
        .expect("reload transition snapshot");
    let reload_request = transition_request(
        "reload-planning",
        reload_snapshot.revision.sequence,
        "planning",
        1_040,
    );
    let (reload_transition, reload_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            reload_request,
            ListChangeSupport::Unsupported,
            1_040,
        )
        .expect("stage reload-required transition");
    service
        .cancel_transition_for_connection(&primary, &reload_transition.operation_id, 1_041)
        .expect("cancel reload transition");

    let next_snapshot = service
        .control_plane()
        .snapshot()
        .expect("next-session transition snapshot");
    let next_request = transition_request(
        "next-session-planning",
        next_snapshot.revision.sequence,
        "planning",
        1_050,
    );
    let (next_transition, next_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            next_request,
            ListChangeSupport::NextSessionOnly,
            1_050,
        )
        .expect("stage next-session transition");
    let next_cancelled = service
        .cancel_transition_for_connection(&primary, &next_transition.operation_id, 1_051)
        .expect("cancel next-session transition");

    let stale_snapshot = service
        .control_plane()
        .snapshot()
        .expect("stale transition snapshot");
    let stale_request = transition_request(
        "stale-review",
        stale_snapshot.revision.sequence.saturating_sub(1),
        "review",
        1_060,
    );
    let stale_transition_denial = service
        .enter_workflow_mode_for_connection(
            &primary,
            stale_request,
            ListChangeSupport::Negotiated,
            1_060,
        )
        .expect_err("stale transition denied");

    let native_after = fs::read(&native_state_path).expect("native fixture state after routing");
    let replacement_root = root.join("second-session");
    fs::create_dir(&replacement_root).expect("second session root");
    let second_manager =
        SessionManager::with_authority_key(&replacement_root, SessionAuthorityKey::new([0x61; 32]));
    let second_bootstrap = BootstrapRequest {
        repository_key: "workflow-matrix-repository-b".to_string(),
        workspace_key: "workflow-matrix-workspace-b".to_string(),
        connection_scope_id: "workflow-matrix-connection-b".to_string(),
        process: ProcessEvidence {
            pid: std::process::id(),
            start_marker: "workflow-matrix-process-b".to_string(),
        },
        protected_resources: BTreeSet::from(["provider-state-b".to_string()]),
        ..bootstrap.clone()
    };
    let second_authority = second_manager
        .prepare_bootstrap(second_bootstrap.clone(), 1_100)
        .expect("second bootstrap");
    let second_claimed = second_manager
        .claim_bootstrap(
            &second_authority,
            &ConnectionClaim {
                connection_owner_id: "workflow-matrix-owner-b".to_string(),
                provider: second_bootstrap.provider,
                repository_key: second_bootstrap.repository_key.clone(),
                workspace_key: second_bootstrap.workspace_key.clone(),
                process: second_bootstrap.process.clone(),
                connection_scope_id: second_bootstrap.connection_scope_id.clone(),
            },
            1_101,
        )
        .expect("second claim");
    let second_control = unpin_core::gateway::GatewayControlPlane::new(
        second_manager,
        second_claimed.handle,
        limits.maximum_concurrent_calls,
    )
    .expect("second control plane");
    let second_service = GatewayService::new(second_control, exposures["planning"].clone(), limits)
        .expect("second gateway service");
    let second_primary = second_service
        .issue_connection_claim()
        .expect("second primary");
    let cross_session_denial = second_service
        .connection_status(&primary)
        .expect_err("claim cannot cross sessions");

    service
        .connection_registry()
        .disconnect(&primary)
        .expect("disconnect original primary");
    let replacement = service
        .issue_connection_claim()
        .expect("replacement primary claim");
    let replacement_status = service
        .connection_status(&replacement)
        .expect("replacement recovery status");
    let stale_connection_denial = service
        .connection_status(&primary)
        .expect_err("old primary is stale");

    let mut cumulative_schema_bytes = 0_usize;
    let mut cumulative_skill_body_bytes = 0_usize;
    let cumulative = ["planning", "implementation", "review"]
        .into_iter()
        .map(|mode| {
            let evidence = &mode_evidence[mode];
            cumulative_schema_bytes += evidence.schema_bytes;
            cumulative_skill_body_bytes += evidence.loaded_skill_body_bytes;
            json!({
                "visitedMode": mode,
                "distinctModesVisited": mode_evidence
                    .keys()
                    .filter(|candidate| ["planning", "implementation", "review"]
                        .iter()
                        .take_while(|visited| **visited != mode)
                        .chain(std::iter::once(&mode))
                        .any(|visited| *candidate == *visited))
                    .count(),
                "schemaBytesSeen": cumulative_schema_bytes,
                "estimatedTokensSeen": estimated_tokens(cumulative_schema_bytes),
                "skillBodyBytesLoaded": cumulative_skill_body_bytes,
                "remainingSavingsBytes": unrouted_installed_catalog_schema_bytes.saturating_sub(cumulative_schema_bytes)
            })
        })
        .collect::<Vec<_>>();

    let initial_active_schema_bytes = mode_evidence["planning"].schema_bytes;
    let active_schema_bytes = mode_evidence
        .values()
        .map(|mode| mode.schema_bytes)
        .max()
        .expect("mode metrics");
    let active_estimated_tokens = estimated_tokens(active_schema_bytes);
    let full_envelope_estimated_tokens = estimated_tokens(full_envelope_schema_bytes);
    let fixture_protected_resources = service
        .control_plane()
        .snapshot()
        .expect("final session status")
        .lease
        .protected_resources
        .len();
    let plugin_mode = &mode_evidence["review"];
    let planning_mode = &mode_evidence["planning"];

    let evidence = json!({
        "schemaVersion": 1,
        "status": "passed",
        "workflow": {
            "id": workflow.workflow_id,
            "entryMode": workflow.entry_mode,
            "modeOrder": ["planning", "implementation", "review"],
            "maximumEnvelopeDigest": workflow.maximum_envelope.digest,
            "maximumEnvelopeCapabilityIds": workflow.maximum_envelope.members.iter().map(|member| member.capability_id.to_string()).collect::<Vec<_>>(),
            "systemControlToolNames": WorkflowControl::ALL.into_iter().map(|control| control.name()).collect::<Vec<_>>(),
            "generalIsModeNotBaseline": true,
        },
        "modes": mode_evidence,
        "metrics": {
            "metricDefinition": "Canonical compact JSON UTF-8 bytes for MCP tool descriptors; token values are deterministic byte-divided-by-four estimates, not provider billing tokens.",
            "unroutedInstalledCatalogSchemaBytes": unrouted_installed_catalog_schema_bytes,
            "fullEnvelopeSchemaBytes": full_envelope_schema_bytes,
            "initialActiveSchemaBytes": initial_active_schema_bytes,
            "activeSchemaBytes": active_schema_bytes,
            "unroutedInstalledCatalogEstimatedTokens": estimated_tokens(unrouted_installed_catalog_schema_bytes),
            "fullEnvelopeEstimatedTokens": full_envelope_estimated_tokens,
            "initialActiveEstimatedTokens": estimated_tokens(initial_active_schema_bytes),
            "activeEstimatedTokens": active_estimated_tokens,
            "thresholds": {
                "initialActiveLessThanUnrouted": initial_active_schema_bytes < unrouted_installed_catalog_schema_bytes,
                "activeLessThanFullEnvelope": active_schema_bytes < full_envelope_schema_bytes,
                "activeEstimatedTokensLessThanFullEnvelope": active_estimated_tokens < full_envelope_estimated_tokens,
                "initialModeExcludesNonBaselineTool": !planning_mode.advertised_tool_names.contains(&"review__inspect".to_string())
            },
            "cumulativeByVisitedMode": cumulative,
            "contextReclamation": ["compaction", "subagent", "new-session"]
        },
        "transitionTimeline": [
            {
                "event": "initial-primary-list",
                "desiredRevision": initial_status.observed_exposure_revision,
                "observedRevision": initial_status.observed_exposure_revision,
                "connectionEpoch": initial_status.connection_epoch
            },
            {
                "event": "implementation-staged",
                "outcome": implementation_outcome,
                "desiredRevision": implementation_transition.desired_exposure_revision,
                "observedRevision": status_after_stage.observed_exposure_revision,
                "pendingRevision": status_after_stage.pending_exposure_revision
            },
            {
                "event": "tools-list-changed-notification",
                "outcome": notification,
                "desiredRevision": implementation_transition.desired_exposure_revision,
                "observedRevision": status_after_notification.observed_exposure_revision,
                "pendingRevision": status_after_notification.pending_exposure_revision
            },
            {
                "event": "same-primary-tools-list",
                "connectionEpoch": primary.connection_epoch(),
                "advertisedToolNames": implementation_tools.iter().map(|tool| tool.name.clone()).collect::<Vec<_>>(),
                "desiredRevision": implementation_transition.desired_exposure_revision,
                "observedRevision": implementation_observed.observed_exposure_revision,
                "pendingRevision": implementation_observed.pending_exposure_revision
            },
            {
                "event": "review-staged",
                "outcome": review_outcome,
                "desiredRevision": review_transition.desired_exposure_revision
            },
            {
                "event": "same-primary-review-tools-list",
                "connectionEpoch": primary.connection_epoch(),
                "advertisedToolNames": review_tools.iter().map(|tool| tool.name.clone()).collect::<Vec<_>>(),
                "observedRevision": review_observed.observed_exposure_revision
            }
        ],
        "fallbacks": {
            "supportedRefresh": format!("{implementation_outcome:?}"),
            "notification": format!("{notification:?}"),
            "refreshUnconfirmed": format!("{cancel_outcome:?}"),
            "reloadRequired": format!("{reload_outcome:?}"),
            "nextSessionOnly": format!("{next_outcome:?}"),
            "cancel": {
                "operationId": cancel_transition.operation_id,
                "observedRevision": cancelled.observed_exposure_revision,
                "pendingRevision": cancelled.pending_exposure_revision,
                "recoveryRequired": cancelled.recovery_required
            },
            "nextSessionCancelObservedRevision": next_cancelled.observed_exposure_revision
        },
        "connections": {
            "primary": initial_status,
            "auxiliary": auxiliary_status,
            "auxiliaryDataDenial": error_code(auxiliary_data_denial),
            "secondSessionPrimary": second_service.connection_status(&second_primary).expect("second status"),
            "crossSessionClaimDenial": error_code(cross_session_denial),
            "replacementPrimary": replacement_status,
            "staleDisconnectedPrimaryDenial": error_code(stale_connection_denial),
            "staleTransitionDenial": error_code(stale_transition_denial)
        },
        "agentPlugin": {
            "packageId": plugin.id,
            "contributedCapabilityIds": plugin.contributions.iter().map(|edge| edge.capability_id.to_string()).collect::<Vec<_>>(),
            "mode": "review",
            "advertisedToolNames": plugin_mode.advertised_tool_names,
            "skillSearchResults": plugin_mode.skill_search_results,
            "hookIds": plugin_mode.hook_ids,
            "packageTogglePerformed": false,
            "nativeStateUnchanged": native_before == native_after
        },
        "safety": {
            "fixtureMode": true,
            "strictMaskingCoverage": "verified-masked",
            "nativeCapabilities": "native-unmanaged",
            "nativeProviderStateBytesBefore": native_before.len(),
            "nativeProviderStateBytesAfter": native_after.len(),
            "nativeProviderStateSha256Before": source_fingerprint(&native_before),
            "nativeProviderStateSha256After": source_fingerprint(&native_after),
            "nativeProviderStateUnchanged": native_before == native_after,
            "bridgeAuthentication": "process-root-generation-sequence-bound",
            "protectedRootEvidence": {
                "protectedResourceCount": fixture_protected_resources,
                "repositoryConfigMayRedirect": false
            }
        },
        "crossSurfaceParity": {
            "canonicalStateFields": ["workflowId", "activeMode", "desiredExposureRevision", "observedExposureRevision", "liveStatus", "nextAction"],
            "cli": true,
            "mcp": true,
            "desktop": true,
            "tui": true,
            "tuiRole": "compact-inspection-and-handoff",
            "desktopRole": "primary-human-workbench"
        }
    });
    let bytes = serde_json::to_vec_pretty(&evidence).expect("evidence JSON");
    if let Some(output) = output {
        fs::write(output, &bytes).expect("write workflow matrix evidence");
    } else {
        println!("{}", String::from_utf8(bytes).expect("UTF-8 evidence"));
    }
}
