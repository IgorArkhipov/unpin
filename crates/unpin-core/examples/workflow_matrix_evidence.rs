use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

use rmcp::ServiceExt;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use unpin_cli::mcp_runtime::{
    GatewayMcpServer, GatewayRuntimeTimeouts, NoGatewayCredentials, primary_gateway_tools,
    serve_gateway_io,
};
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

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn unix_now() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("workflow matrix clock")
        .as_secs();
    i64::try_from(seconds).expect("workflow matrix clock range")
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

fn canonical_schema_bytes(values: &[Value]) -> usize {
    serde_json::to_vec(values)
        .expect("canonical schema JSON")
        .len()
}

fn tool_names(values: &[Value]) -> Vec<String> {
    values
        .iter()
        .filter_map(|descriptor| descriptor["name"].as_str().map(str::to_string))
        .collect()
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
    gateway_tools_list_names: Vec<String>,
    expected_tool_descriptors: Vec<Value>,
    observed_tool_descriptors: Vec<Value>,
    mcp_observation_source: &'static str,
    skill_search_results: Vec<Value>,
    loaded_skill_body_bytes: usize,
    hook_ids: Vec<String>,
    schema_bytes: usize,
    estimated_tokens: usize,
}

const MCP_OBSERVATION_SOURCE: &str = "GatewayMcpServer RMCP tools/list";

fn rmcp_list_tools(
    service: &std::sync::Arc<GatewayService>,
    claim: &unpin_core::gateway::GatewayConnectionClaim,
) -> Vec<Value> {
    let lease_expiry = service
        .control_plane()
        .snapshot()
        .expect("RMCP witness session snapshot")
        .lease
        .lease_expires_at_unix;
    let now_unix = unix_now();
    assert!(
        lease_expiry > now_unix,
        "RMCP witness requires a live fixture lease"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("workflow evidence RMCP runtime");
    runtime.block_on(async {
        let server = GatewayMcpServer::new(
            std::sync::Arc::clone(service),
            std::sync::Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts::default(),
        )
        .with_connection_claim(claim.clone());
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(server_io);
            serve_gateway_io(server, read, write).await
        });
        let mut client = ().serve(client_io).await.expect("connect RMCP witness");
        let mut tools = client
            .list_all_tools()
            .await
            .expect("RMCP tools/list witness")
            .into_iter()
            .map(|tool| serde_json::to_value(tool).expect("RMCP tool descriptor JSON"))
            .collect::<Vec<_>>();
        tools.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        client
            .close_with_timeout(std::time::Duration::from_secs(2))
            .await
            .expect("close RMCP witness client");
        server_task
            .await
            .expect("RMCP witness task")
            .expect("serve RMCP witness");
        tools
    })
}

fn mode_evidence(mode: &str, exposure: &GatewayExposure, observed_tools: &[Value]) -> ModeEvidence {
    let expected_tool_descriptors = expected_tool_descriptors(exposure);
    let advertised_tool_names = tool_names(&expected_tool_descriptors);
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
    let schema_bytes = canonical_schema_bytes(observed_tools);
    ModeEvidence {
        mode: mode.to_string(),
        revision: exposure.pinned().revision.clone(),
        advertised_tool_names,
        gateway_tools_list_names: observed_tools
            .iter()
            .filter_map(|descriptor| descriptor["name"].as_str().map(str::to_string))
            .collect(),
        expected_tool_descriptors,
        observed_tool_descriptors: observed_tools.to_vec(),
        mcp_observation_source: MCP_OBSERVATION_SOURCE,
        skill_search_results,
        loaded_skill_body_bytes,
        hook_ids,
        schema_bytes,
        estimated_tokens: estimated_tokens(schema_bytes),
    }
}

fn expected_tool_descriptors(exposure: &GatewayExposure) -> Vec<Value> {
    let mut descriptors = primary_gateway_tools(exposure.tools().descriptors())
        .expect("production primary gateway descriptors")
        .into_iter()
        .map(|tool| serde_json::to_value(tool).expect("expected RMCP tool descriptor JSON"))
        .collect::<Vec<_>>();
    descriptors.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    descriptors
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
    let fixture_now = unix_now();
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
        lease_expires_at_unix: fixture_now.saturating_add(3_000),
    };
    let authority = manager
        .prepare_bootstrap(bootstrap.clone(), fixture_now)
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
            fixture_now.saturating_add(1),
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
            fixture_now.saturating_add(2),
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
    let control = unpin_core::gateway::GatewayControlPlane::new(
        manager,
        claimed.handle,
        limits.maximum_concurrent_calls,
    )
    .expect("gateway control plane");
    let service = std::sync::Arc::new(
        GatewayService::new(control, exposures["planning"].clone(), limits)
            .expect("gateway service"),
    );
    for mode in ["implementation", "review"] {
        service
            .register_workflow_exposure(exposures[mode].clone())
            .expect("register workflow exposure");
    }
    let primary = service.issue_connection_claim().expect("primary claim");
    let auxiliary = service.accept_connection().expect("auxiliary claim");
    let initial_status = service.connection_status(&primary).expect("initial status");
    let initial_tools = rmcp_list_tools(&service, &primary);
    let auxiliary_status = service
        .connection_status(&auxiliary)
        .expect("auxiliary status");
    let auxiliary_data_denial = service
        .list_tools_for_connection(&auxiliary, fixture_now.saturating_add(3))
        .expect_err("auxiliary is control-only");

    let implementation_request = transition_request(
        "enter-implementation",
        pinned.revision.sequence,
        "implementation",
        fixture_now.saturating_add(10),
    );
    let (implementation_transition, implementation_outcome) = service
        .enter_workflow_mode_for_connection(
            &auxiliary,
            implementation_request,
            ListChangeSupport::Negotiated,
            fixture_now.saturating_add(10),
        )
        .expect("stage implementation transition");
    let status_after_stage = service.connection_status(&primary).expect("staged status");
    let _pre_notification_tools = service
        .list_tools_for_connection(&primary, fixture_now.saturating_add(11))
        .expect("pre-notification list");
    let notification = service
        .notify_tools_changed_for_connection(&primary, fixture_now.saturating_add(12))
        .expect("notify primary");
    let status_after_notification = service
        .connection_status(&primary)
        .expect("notification status");
    let implementation_tools = rmcp_list_tools(&service, &primary);
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
        fixture_now.saturating_add(20),
    );
    let (review_transition, review_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            review_request,
            ListChangeSupport::Negotiated,
            fixture_now.saturating_add(20),
        )
        .expect("stage review transition");
    service
        .notify_tools_changed_for_connection(&primary, fixture_now.saturating_add(21))
        .expect("notify review transition");
    let review_tools = rmcp_list_tools(&service, &primary);

    let mut maximum_descriptors = ["planning", "implementation", "review"]
        .into_iter()
        .flat_map(|mode| expected_tool_descriptors(&exposures[mode]))
        .collect::<Vec<_>>();
    maximum_descriptors.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    maximum_descriptors.dedup_by(|left, right| left["name"] == right["name"]);
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
    let review_observed = service
        .connection_status(&primary)
        .expect("review observed status");
    let mode_evidence = BTreeMap::from([
        (
            "planning".to_string(),
            mode_evidence("planning", &exposures["planning"], &initial_tools),
        ),
        (
            "implementation".to_string(),
            mode_evidence(
                "implementation",
                &exposures["implementation"],
                &implementation_tools,
            ),
        ),
        (
            "review".to_string(),
            mode_evidence("review", &exposures["review"], &review_tools),
        ),
    ]);

    let cancel_snapshot = service
        .control_plane()
        .snapshot()
        .expect("cancel transition snapshot");
    let cancel_request = transition_request(
        "cancel-planning",
        cancel_snapshot.revision.sequence,
        "planning",
        fixture_now.saturating_add(30),
    );
    let (cancel_transition, cancel_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            cancel_request,
            ListChangeSupport::NotificationOnly,
            fixture_now.saturating_add(30),
        )
        .expect("stage refresh-unconfirmed transition");
    let cancelled = service
        .cancel_transition_for_connection(
            &primary,
            &cancel_transition.operation_id,
            fixture_now.saturating_add(31),
        )
        .expect("cancel transition");

    let reload_snapshot = service
        .control_plane()
        .snapshot()
        .expect("reload transition snapshot");
    let reload_request = transition_request(
        "reload-planning",
        reload_snapshot.revision.sequence,
        "planning",
        fixture_now.saturating_add(40),
    );
    let (reload_transition, reload_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            reload_request,
            ListChangeSupport::Unsupported,
            fixture_now.saturating_add(40),
        )
        .expect("stage reload-required transition");
    service
        .cancel_transition_for_connection(
            &primary,
            &reload_transition.operation_id,
            fixture_now.saturating_add(41),
        )
        .expect("cancel reload transition");

    let next_snapshot = service
        .control_plane()
        .snapshot()
        .expect("next-session transition snapshot");
    let next_request = transition_request(
        "next-session-planning",
        next_snapshot.revision.sequence,
        "planning",
        fixture_now.saturating_add(50),
    );
    let (next_transition, next_outcome) = service
        .enter_workflow_mode_for_connection(
            &primary,
            next_request,
            ListChangeSupport::NextSessionOnly,
            fixture_now.saturating_add(50),
        )
        .expect("stage next-session transition");
    let next_cancelled = service
        .cancel_transition_for_connection(
            &primary,
            &next_transition.operation_id,
            fixture_now.saturating_add(51),
        )
        .expect("cancel next-session transition");

    let stale_snapshot = service
        .control_plane()
        .snapshot()
        .expect("stale transition snapshot");
    let stale_request = transition_request(
        "stale-review",
        stale_snapshot.revision.sequence.saturating_sub(1),
        "review",
        fixture_now.saturating_add(60),
    );
    let stale_transition_denial = service
        .enter_workflow_mode_for_connection(
            &primary,
            stale_request,
            ListChangeSupport::Negotiated,
            fixture_now.saturating_add(60),
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
        .prepare_bootstrap(second_bootstrap.clone(), fixture_now.saturating_add(100))
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
            fixture_now.saturating_add(101),
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
    let final_snapshot = service
        .control_plane()
        .snapshot()
        .expect("surface coverage snapshot");
    let final_workflow = final_snapshot
        .lease
        .workflow
        .as_ref()
        .expect("surface coverage workflow");
    let gateway_next_action = if final_snapshot.lease.desired_exposure
        == final_snapshot.lease.observed_exposure
        && final_snapshot.lease.admission_open
    {
        "continue-in-active-mode"
    } else {
        "reconcile-workflow-exposure"
    };
    let gateway_observation = json!({
        "workflowId": final_workflow.workflow_id,
        "activeMode": final_workflow.active_mode,
        "desiredExposureRevision": final_snapshot.lease.desired_exposure.revision,
        "observedExposureRevision": final_snapshot.lease.observed_exposure.revision,
        "liveStatus": final_snapshot.lease.live_status,
        "nextAction": gateway_next_action,
    });
    let mcp_next_action = if review_observed.observed_exposure_revision
        == final_snapshot.lease.desired_exposure.revision
        && final_snapshot.lease.admission_open
    {
        "continue-in-active-mode"
    } else {
        "reconcile-workflow-exposure"
    };
    let mcp_observation = json!({
           "workflowId": final_workflow.workflow_id,
           "activeMode": final_workflow.active_mode,
           "desiredExposureRevision": final_snapshot.lease.desired_exposure.revision,
           "observedExposureRevision": review_observed.observed_exposure_revision,
           "liveStatus": final_snapshot.lease.live_status,
           "nextAction": mcp_next_action,
    "observationSource": MCP_OBSERVATION_SOURCE,
        "observedToolNames": tool_names(&review_tools),
       });

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
                "advertisedToolNames": tool_names(&implementation_tools),
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
                "advertisedToolNames": tool_names(&review_tools),
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
        "surfaceCoverage": {
            "canonicalObservedFields": ["workflowId", "activeMode", "desiredExposureRevision", "observedExposureRevision", "liveStatus", "nextAction"],
            "roles": {
                "gateway": {"role": "authoritative-live-runtime"},
                "mcp": {"role": "gateway-tools-list-and-read-only-session-planning"},
                "cli": {"role": "definition-validation-and-human-launch-handoff"},
                "desktop": {"role": "primary-human-workbench"},
                "tui": {
                    "role": "projection-and-handoff",
                    "editing": false,
                    "liveParityClaimed": false
                }
            },
            "observations": {
                "gateway": gateway_observation,
                "mcp": mcp_observation
            }
        }
    });
    let bytes = serde_json::to_vec_pretty(&evidence).expect("evidence JSON");
    if let Some(output) = output {
        fs::write(output, &bytes).expect("write workflow matrix evidence");
    } else {
        println!("{}", String::from_utf8(bytes).expect("UTF-8 evidence"));
    }
}
