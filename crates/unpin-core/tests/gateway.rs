use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        VerifiedApproval,
    },
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ProviderView,
    },
    config::get_session_lease_path,
    discovery::DiscoveryLayer,
    gateway::{
        CredentialBinding, GatewayControlPlane, GatewayError, GatewayExposure,
        GatewayHookRegistration, GatewayLimits, GatewayRefreshOutcome, GatewayService,
        ListChangeSupport, UpstreamIdentity, UpstreamToolDescriptor, UpstreamToolRegistration,
        UpstreamValidationError,
    },
    hooks::{
        HookAction, HookActionOutcome, HookBeforeDecision, HookEventFamily, HookFailurePolicy,
        HookHandler, HookHandlerSpec, HookInvocationChain, HookMatcher, HookOwnership,
        HookRouteOwner, HookSourceLayer, HookTransformCapabilities,
    },
    profiles::{
        CapabilityLockSnapshot, CapabilityLockState, PROFILE_DEFINITION_VERSION, ProfileDefinition,
        ProfileSourceScope, compile_profile,
    },
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, LiveExposureStatus,
        PinnedExposure, PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary directory");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary directory");
        Self {
            _inner: inner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn verified(expectation: ApprovalExpectation) -> VerifiedApproval {
    let issuer = ApprovalIssuer::new(
        ApprovalKey::new([9; 32]),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .unwrap();
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
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
        .unwrap();
    ApprovalVerifier::new(ApprovalKey::new([9; 32]))
        .verify(&receipt, &expectation, 1_100)
        .unwrap()
}

fn gateway_hook(
    provider: ProviderId,
    id: &str,
    event_family: HookEventFamily,
    failure_policy: HookFailurePolicy,
    transformations: HookTransformCapabilities,
    profile_digest: &str,
) -> HookHandler {
    reviewed_gateway_hook_action(
        provider,
        id,
        event_family,
        failure_policy,
        transformations,
        HookAction::http(format!("https://{id}.example.test")).unwrap(),
        profile_digest,
    )
}

fn reviewed_gateway_hook_action(
    provider: ProviderId,
    id: &str,
    event_family: HookEventFamily,
    failure_policy: HookFailurePolicy,
    transformations: HookTransformCapabilities,
    action: HookAction,
    profile_digest: &str,
) -> HookHandler {
    let handler = HookHandler::new(HookHandlerSpec {
        id: id.to_string(),
        provider,
        native_event: match event_family {
            HookEventFamily::BeforeTool => "BeforeTool",
            HookEventFamily::AfterToolSuccess => "AfterToolSuccess",
            HookEventFamily::AfterToolFailure => "AfterToolFailure",
            _ => "ProviderEvent",
        }
        .to_string(),
        event_family,
        matcher: HookMatcher::any(),
        action,
        order: 0,
        timeout_ms: 10_000,
        failure_policy,
        source_layer: HookSourceLayer::Session,
        ownership: HookOwnership::User,
        route_owner: HookRouteOwner::Gateway,
        enabled: true,
        transformations,
    })
    .unwrap();
    let expectation = handler
        .trust_approval_expectation(
            profile_digest,
            "unpin-ui",
            "unpin-core",
            "repository-a",
            "workspace-a",
            "session-a",
        )
        .unwrap();
    handler
        .review(&verified(expectation), profile_digest)
        .unwrap()
}

fn source_fingerprint(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("valid capability id")
}

fn record(
    value: &str,
    kind: CapabilityKind,
    source_path: &Path,
    fingerprint: char,
) -> CatalogRecord {
    let capability_id = id(value);
    let source_path = source_path.to_string_lossy().into_owned();
    let source = fs::read_to_string(&source_path).unwrap_or_default();
    CatalogRecord {
        id: capability_id,
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
            observation: "gateway-fixture".to_string(),
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
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    }
}

fn compile(
    catalog: &Catalog,
    profile_id: &str,
    members: Vec<CapabilityId>,
) -> unpin_core::profiles::CompiledProfileRevision {
    compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: profile_id.to_string(),
            display_name: profile_id.to_string(),
            description: None,
            members,
            provider_members: BTreeMap::new(),
        },
        catalog,
        ProfileSourceScope::Session,
    )
    .expect("compile profile")
}

fn pin(
    revision_character: char,
    profile: &unpin_core::profiles::CompiledProfileRevision,
) -> PinnedExposure {
    PinnedExposure {
        revision: digest(revision_character),
        profile: PinnedProfile::Profile {
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.digest.clone(),
            origin_scope: profile.origin.scope,
            definition_digest: profile.origin.definition_digest.clone(),
        },
        capability_locks: None,
    }
}

fn registration(
    record: &CatalogRecord,
    registration_id: &str,
    server_id: &str,
    tool_name: &str,
    endpoint: &str,
) -> UpstreamToolRegistration {
    UpstreamToolRegistration {
        registration_id: registration_id.to_string(),
        capability_id: record.id.clone(),
        capability_fingerprint: record.fingerprint.clone(),
        provider: ProviderId::Codex,
        identity: UpstreamIdentity::streamable_http(server_id, endpoint).expect("HTTP identity"),
        credential: None,
        descriptor: UpstreamToolDescriptor {
            name: tool_name.to_string(),
            title: Some(format!("{tool_name} title")),
            description: Some(format!("{tool_name} description")),
            input_schema: json!({
                "type": "object",
                "properties": {"value": {"type": "string"}}
            }),
            output_schema: Some(json!({"type": "object"})),
            annotations: Some(json!({"readOnlyHint": true})),
            execution: Some(json!({"taskSupport": "optional"})),
        },
    }
}

fn establish(
    root: &Path,
    workspace: &str,
    connection: &str,
    exposure: PinnedExposure,
) -> (SessionManager, unpin_core::sessions::ClaimedSession) {
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x53; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository-a".to_string(),
        workspace_key: workspace.to_string(),
        workspace_revision: Some(digest('1')),
        exposure,
        process: ProcessEvidence {
            pid: 42,
            start_marker: format!("start-{workspace}"),
        },
        connection_scope_id: connection.to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from([format!("resource-{workspace}")]),
        lease_expires_at_unix: 20_000,
    };
    let claim = ConnectionClaim {
        connection_owner_id: format!("owner-{workspace}"),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = manager
        .prepare_bootstrap(request, 1_000)
        .expect("prepare bootstrap");
    let session = manager
        .claim_bootstrap(&authority, &claim, 1_001)
        .expect("claim bootstrap");
    (manager, session)
}

fn service(
    root: &Path,
    workspace: &str,
    connection: &str,
    exposure: GatewayExposure,
    limits: GatewayLimits,
) -> GatewayService {
    let (manager, session) = establish(root, workspace, connection, exposure.pinned().clone());
    let control =
        GatewayControlPlane::new(manager, session.handle, limits.maximum_concurrent_calls)
            .expect("control plane");
    GatewayService::new(control, exposure, limits).expect("gateway service")
}

#[test]
fn skill_metadata_is_scoped_and_body_is_loaded_only_by_opaque_reference() {
    let temp = TempDir::new();
    let skill_path = temp.path().join("review.md");
    fs::write(&skill_path, "# Peer review\nUse focused review.").expect("write skill");
    let selected = record("peer-review", CapabilityKind::Skill, &skill_path, 'a');
    let hidden_path = temp.path().join("deploy.md");
    fs::write(&hidden_path, "# Deploy\nHidden.").expect("write hidden skill");
    let hidden = record("deploy", CapabilityKind::Skill, &hidden_path, 'b');
    let catalog = Catalog::from_records([selected.clone(), hidden]).expect("catalog");
    let profile = compile(&catalog, "review", vec![selected.id.clone()]);
    let pinned = pin('e', &profile);
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pinned,
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        Vec::new(),
        limits,
    )
    .expect("exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", exposure, limits);

    let matches = service
        .search_skills("review", 10, 1_010)
        .expect("search skills");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].name, "peer-review");
    assert!(
        !serde_json::to_string(&matches)
            .expect("metadata JSON")
            .contains("Use focused")
    );
    assert!(
        service
            .search_skills("deploy", 10, 1_011)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        service.load_skill("skill_unknown", 1_012),
        Err(GatewayError::CapabilityUnavailable)
    ));
    let loaded = service
        .load_skill(&matches[0].reference, 1_013)
        .expect("load selected skill");
    assert!(loaded.body.contains("Use focused review"));

    fs::write(&skill_path, "# Peer review\nChanged after pin.").expect("mutate skill");
    assert!(matches!(
        service.load_skill(&matches[0].reference, 1_014),
        Err(GatewayError::SkillContentChanged)
    ));
}

#[test]
fn pinned_global_locks_override_profile_members_in_gateway_projection() {
    let temp = TempDir::new();
    let selected_path = temp.path().join("selected.md");
    fs::write(&selected_path, "# Selected\nProfile member.").unwrap();
    let forced_path = temp.path().join("forced.md");
    fs::write(&forced_path, "# Forced\nGlobal lock.").unwrap();
    let selected = record("selected", CapabilityKind::Skill, &selected_path, 'a');
    let forced = record("forced", CapabilityKind::Skill, &forced_path, 'b');
    let catalog = Catalog::from_records([selected.clone(), forced.clone()]).unwrap();
    let profile = compile(&catalog, "locked", vec![selected.id.clone()]);
    let mut pinned = pin('e', &profile);
    pinned.capability_locks = Some(Box::new(
        CapabilityLockSnapshot::compile(
            ProviderId::Codex,
            BTreeMap::from([
                (selected.id.clone(), CapabilityLockState::HardDisabled),
                (forced.id.clone(), CapabilityLockState::HardEnabled),
            ]),
        )
        .unwrap(),
    ));

    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pinned,
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        Vec::new(),
        limits,
    )
    .expect("lock-aware gateway exposure");
    let service = service(
        temp.path(),
        "workspace-a",
        "connection-locks",
        exposure,
        limits,
    );
    assert!(
        service
            .search_skills("selected", 10, 1_010)
            .unwrap()
            .is_empty()
    );
    let forced_matches = service.search_skills("forced", 10, 1_011).unwrap();
    assert_eq!(forced_matches.len(), 1);
    assert_eq!(forced_matches[0].name, "forced");
}

#[test]
fn skill_registry_canonicalizes_safe_noncanonical_source_paths() {
    let temp = TempDir::new();
    let child = temp.path().join("child");
    fs::create_dir(&child).expect("child directory");
    let canonical = temp.path().join("review.md");
    fs::write(&canonical, "# Review\nCanonical body.").expect("write skill");
    let noncanonical = child.join("..").join("review.md");
    let selected = record("peer-review", CapabilityKind::Skill, &noncanonical, 'a');
    let catalog = Catalog::from_records([selected.clone()]).expect("catalog");
    let profile = compile(&catalog, "review", vec![selected.id.clone()]);
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        Vec::new(),
        limits,
    )
    .expect("exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", exposure, limits);
    let reference = service.search_skills("review", 1, 1_010).unwrap()[0]
        .reference
        .clone();

    assert_eq!(
        service.load_skill(&reference, 1_011).unwrap().body,
        "# Review\nCanonical body."
    );
}

#[test]
fn tool_projection_preserves_protocol_fields_and_uses_opaque_dispatch() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("review-tool", CapabilityKind::McpTool, &source, 'c');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let pinned = pin('e', &profile);
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pinned,
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration-a",
            "review",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", exposure, limits);
    let projected = service.list_tools(1_010).expect("list tools");
    assert_eq!(projected.len(), 1);
    assert_eq!(projected[0].name, "review__run");
    assert_eq!(
        projected[0].annotations,
        Some(json!({"readOnlyHint": true}))
    );
    assert_eq!(
        projected[0].execution,
        Some(json!({"taskSupport": "optional"}))
    );
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("registration-a")
    );

    let mut permit = service
        .data_plane()
        .admit_tool(&projected[0].name, &json!({"value": "ok"}), 1_011)
        .expect("admit tool");
    assert_eq!(permit.tool().registration_id(), Some("registration-a"));
    assert_eq!(permit.tool().upstream_name(), Some("run"));
    service
        .data_plane()
        .finish_tool(&mut permit, &json!({"ok": true}), 1_012)
        .expect("finish tool");
}

#[test]
fn deterministic_collisions_receive_stable_suffixes() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let one = record("tool-one", CapabilityKind::McpTool, &source, 'a');
    let two = record("tool-two", CapabilityKind::McpTool, &source, 'b');
    let catalog = Catalog::from_records([one.clone(), two.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![one.id.clone(), two.id.clone()]);
    let pinned = pin('e', &profile);
    let limits = GatewayLimits::default();
    let compile_with_order = |reverse: bool| {
        let first = registration(
            &one,
            "registration-one",
            "shared",
            "run",
            "https://one.example/mcp",
        );
        let second = registration(
            &two,
            "registration-two",
            "shared",
            "run",
            "https://two.example/mcp",
        );
        let registrations = if reverse {
            vec![second, first]
        } else {
            vec![first, second]
        };
        GatewayExposure::compile(
            pinned.clone(),
            ProviderId::Codex,
            &catalog,
            Some(&profile),
            registrations,
            limits,
        )
        .expect("collision exposure")
        .tools()
        .descriptors()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>()
    };
    let forward = compile_with_order(false);
    let reverse = compile_with_order(true);
    assert_eq!(forward, reverse);
    assert_eq!(forward.len(), 2);
    assert!(forward.iter().all(|name| name.starts_with("shared__run__")));
    assert_ne!(forward[0], forward[1]);
}

#[test]
fn collisions_created_by_public_name_truncation_receive_stable_suffixes() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let one = record("tool-one", CapabilityKind::McpTool, &source, 'a');
    let two = record("tool-two", CapabilityKind::McpTool, &source, 'b');
    let catalog = Catalog::from_records([one.clone(), two.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![one.id.clone(), two.id.clone()]);
    let prefix = "t".repeat(80);
    let exposure = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![
            registration(
                &one,
                "registration-one",
                &"s".repeat(100),
                &format!("{prefix}-one"),
                "https://one.example/mcp",
            ),
            registration(
                &two,
                "registration-two",
                &"s".repeat(100),
                &format!("{prefix}-two"),
                "https://two.example/mcp",
            ),
        ],
        GatewayLimits::default(),
    )
    .expect("truncated collision exposure");
    let names = exposure
        .tools()
        .descriptors()
        .into_iter()
        .map(|tool| tool.name)
        .collect::<Vec<_>>();

    assert_eq!(names.len(), 2);
    assert_ne!(names[0], names[1]);
    assert!(names.iter().all(|name| name.len() <= 128));
}

#[test]
fn tool_presentation_text_rejects_terminal_control_sequences() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let mut unsafe_registration = registration(
        &tool,
        "registration",
        "server",
        "run",
        "https://example.test/mcp",
    );
    unsafe_registration.descriptor.title = Some("unsafe\u{1b}[31m".to_string());

    assert!(matches!(
        GatewayExposure::compile(
            pin('e', &profile),
            ProviderId::Codex,
            &catalog,
            Some(&profile),
            vec![unsafe_registration],
            GatewayLimits::default(),
        ),
        Err(GatewayError::Upstream(_))
    ));
}

#[test]
fn credentials_are_bound_to_exact_upstream_identity() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let pinned = pin('e', &profile);
    let identity_a =
        UpstreamIdentity::streamable_http("server", "https://a.example/mcp").expect("identity A");
    let identity_b =
        UpstreamIdentity::streamable_http("server", "https://b.example/mcp").expect("identity B");
    let credential = CredentialBinding::new("credential-a", &identity_a).expect("credential");
    let mut mismatched = registration(
        &tool,
        "registration",
        "server",
        "run",
        "https://b.example/mcp",
    );
    mismatched.identity = identity_b;
    mismatched.credential = Some(credential);
    assert!(matches!(
        GatewayExposure::compile(
            pinned,
            ProviderId::Codex,
            &catalog,
            Some(&profile),
            vec![mismatched],
            GatewayLimits::default(),
        ),
        Err(GatewayError::Upstream(_))
    ));
}

#[cfg(unix)]
#[test]
fn stdio_identity_detects_executable_content_drift() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let executable = temp.path().join("mcp-server");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    let identity =
        UpstreamIdentity::stdio("server", &executable, Vec::new()).expect("stdio identity");

    fs::write(&executable, "#!/bin/sh\nexit 1\n").expect("replace executable content");

    assert!(matches!(
        identity.verify(),
        Err(UpstreamValidationError::IdentityMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn stdio_identity_detects_interpreter_script_argument_drift() {
    let temp = TempDir::new();
    let script = temp.path().join("server.sh");
    fs::write(&script, "exit 0\n").expect("write interpreter script");
    let shell = fs::canonicalize("/bin/sh").expect("canonical shell");
    let identity =
        UpstreamIdentity::stdio("server", shell, vec![script.to_string_lossy().into_owned()])
            .expect("review interpreter and script");

    fs::write(&script, "exit 9\n").expect("mutate interpreter script");

    assert!(matches!(
        identity.verify(),
        Err(UpstreamValidationError::IdentityMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn stdio_identity_rejects_ambiguous_interpreter_options_and_missing_scripts() {
    let temp = TempDir::new();
    let script = temp.path().join("server.sh");
    fs::write(&script, "exit 0\n").expect("write interpreter script");
    let shell = fs::canonicalize("/bin/sh").expect("canonical shell");

    assert!(matches!(
        UpstreamIdentity::stdio(
            "server",
            &shell,
            vec!["-x".to_string(), script.to_string_lossy().into_owned()],
        ),
        Err(UpstreamValidationError::UnsafeExecutable)
    ));
    assert!(matches!(
        UpstreamIdentity::stdio(
            "server",
            &shell,
            vec![
                temp.path()
                    .join("missing.sh")
                    .to_string_lossy()
                    .into_owned()
            ],
        ),
        Err(UpstreamValidationError::ExecutableUnavailable { .. })
    ));
    UpstreamIdentity::stdio(
        "server",
        shell,
        vec!["-c".to_string(), "exit 0".to_string()],
    )
    .expect("inline code is fully bound by structured arguments");
}

#[cfg(unix)]
#[test]
fn stdio_identity_detects_shebang_interpreter_drift() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let interpreter = temp.path().join("reviewed-interpreter");
    fs::write(&interpreter, "#!/bin/sh\nexec /bin/sh \"$@\"\n").expect("write interpreter");
    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700))
        .expect("make interpreter executable");
    let executable = temp.path().join("mcp-server");
    fs::write(
        &executable,
        format!("#!{}\nexit 0\n", interpreter.display()),
    )
    .expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    let identity = UpstreamIdentity::stdio("server", &executable, Vec::new())
        .expect("review complete interpreter chain");

    fs::write(&interpreter, "#!/bin/sh\nexit 9\n").expect("mutate interpreter");

    assert!(matches!(
        identity.verify(),
        Err(UpstreamValidationError::IdentityMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn stdio_identity_resolves_env_shebang_from_reviewed_path_and_binds_environment() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).expect("create PATH directory");
    let interpreter = bin.join("unpin-test-interpreter");
    fs::write(&interpreter, "#!/bin/sh\nexec /bin/sh \"$@\"\n").expect("write interpreter");
    fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o700))
        .expect("make interpreter executable");
    let executable = temp.path().join("mcp-server");
    fs::write(
        &executable,
        "#!/usr/bin/env unpin-test-interpreter\nexit 0\n",
    )
    .expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    let environment = BTreeMap::from([("PATH".to_string(), bin.to_string_lossy().into_owned())]);
    let identity =
        UpstreamIdentity::stdio_with_environment("server", &executable, Vec::new(), environment)
            .expect("review PATH interpreter");
    identity.verify().expect("unchanged identity");

    let mut changed_environment = identity.clone();
    changed_environment
        .environment
        .insert("LANG".to_string(), "C".to_string());
    assert!(matches!(
        changed_environment.verify(),
        Err(UpstreamValidationError::IdentityMismatch)
    ));

    fs::write(&interpreter, "#!/bin/sh\nexit 9\n").expect("mutate PATH interpreter");
    assert!(matches!(
        identity.verify(),
        Err(UpstreamValidationError::IdentityMismatch)
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn prepared_stdio_keeps_only_descriptor_backed_files_inheritable() {
    use std::os::unix::fs::PermissionsExt;

    const F_GETFD: std::ffi::c_int = 1;
    const FD_CLOEXEC: std::ffi::c_int = 1;
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
    }

    let temp = TempDir::new();
    let executable = temp.path().join("mcp-server");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    let identity =
        UpstreamIdentity::stdio("server", &executable, Vec::new()).expect("review stdio identity");
    let prepared = identity
        .prepare_stdio_execution()
        .expect("prepare stdio execution");
    let descriptors = prepared.inherited_file_descriptors();

    assert_eq!(descriptors.len(), 1, "only script snapshot is inherited");
    assert!(prepared.arguments()[0].starts_with("/proc/self/fd/"));
    for descriptor in descriptors {
        // SAFETY: descriptor belongs to live prepared execution; F_GETFD has no third argument.
        let flags = unsafe { fcntl(descriptor, F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & FD_CLOEXEC, 0, "parent descriptor stays CLOEXEC");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_stdio_uses_owned_snapshot_paths_without_inheriting_descriptors() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let executable = temp.path().join("mcp-server");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").expect("write executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("make executable");
    let identity =
        UpstreamIdentity::stdio("server", &executable, Vec::new()).expect("review stdio identity");
    let prepared = identity
        .prepare_stdio_execution()
        .expect("prepare stdio execution");
    let snapshot = PathBuf::from(&prepared.arguments()[0]);

    assert!(prepared.inherited_file_descriptors().is_empty());
    assert!(snapshot.is_file());
    drop(prepared);
    assert!(
        !snapshot.exists(),
        "snapshot removed when execution is dropped"
    );
}

#[test]
fn cleartext_http_accepts_all_loopback_forms() {
    for endpoint in [
        "http://LOCALHOST:8080/mcp",
        "http://127.0.0.2:8080/mcp",
        "http://127.255.255.254/mcp",
        "http://[::1]:8080/mcp",
        "http://[0:0:0:0:0:0:0:1]/mcp",
    ] {
        UpstreamIdentity::streamable_http("server", endpoint)
            .unwrap_or_else(|error| panic!("{endpoint} should be loopback: {error}"));
    }
    for endpoint in ["http://128.0.0.1/mcp", "http://localhost.example/mcp"] {
        assert!(matches!(
            UpstreamIdentity::streamable_http("server", endpoint),
            Err(UpstreamValidationError::InsecureRemoteEndpoint)
        ));
    }
}

#[test]
fn malformed_bracketed_ipv6_authorities_are_rejected() {
    for endpoint in [
        "https://[::1]abc/mcp",
        "https://[::1]::8080/mcp",
        "https://[::1]:0/mcp",
        "https://[::1]:nope/mcp",
    ] {
        assert!(matches!(
            UpstreamIdentity::streamable_http("server", endpoint),
            Err(UpstreamValidationError::InvalidEndpoint)
        ));
    }
}

#[test]
fn refresh_keeps_admitted_calls_pinned_and_rejects_removed_tools() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let initial_pin = pin('e', &profile);
    let limits = GatewayLimits::default();
    let initial = GatewayExposure::compile(
        initial_pin,
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("initial exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", initial, limits);
    let name = service.list_tools(1_010).unwrap()[0].name.clone();
    let mut admitted = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_011)
        .expect("old call admitted");
    let hook_call_context = admitted.hook_call_context();

    let empty_pin = PinnedExposure {
        revision: digest('f'),
        profile: PinnedProfile::None,
        capability_locks: None,
    };
    service
        .control_plane()
        .request_exposure(empty_pin.clone(), 1_012)
        .expect("request empty exposure");
    assert!(matches!(
        service.data_plane().admit_tool(&name, &json!({}), 1_012),
        Err(GatewayError::CapabilityUnavailable)
    ));
    let empty = GatewayExposure::compile(
        empty_pin,
        ProviderId::Codex,
        &catalog,
        None,
        Vec::new(),
        limits,
    )
    .expect("empty exposure");
    assert_eq!(
        service
            .stage_refresh(empty, ListChangeSupport::Negotiated, 1_013)
            .expect("stage refresh"),
        GatewayRefreshOutcome::NotificationRequired
    );
    service
        .validate_notified_exposure_is_current()
        .expect("notification sent");
    assert_eq!(
        service.control_plane().status().unwrap().live_status,
        LiveExposureStatus::Configured
    );
    assert!(service.list_tools(1_015).unwrap().is_empty());
    assert!(matches!(
        service.data_plane().admit_tool(&name, &json!({}), 1_016),
        Err(GatewayError::CapabilityUnavailable)
    ));
    assert!(matches!(
        service.data_plane().admit_hook_tool(
            &hook_call_context,
            "server",
            "run",
            &json!({}),
            1_016,
            HookInvocationChain::default(),
        ),
        Err(GatewayError::CapabilityUnavailable)
    ));
    service
        .data_plane()
        .finish_tool(&mut admitted, &json!({"ok": true}), 1_017)
        .expect("old admitted call finishes");
    assert_eq!(service.control_plane().status().unwrap().in_flight_calls, 0);
}

#[test]
fn stale_pending_refresh_cannot_replace_newer_desired_exposure() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let limits = GatewayLimits::default();
    let initial = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("initial exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", initial, limits);
    let original = service.list_tools(1_010).expect("original tools");
    let stale_pin = PinnedExposure {
        revision: digest('f'),
        profile: PinnedProfile::None,
        capability_locks: None,
    };
    service
        .control_plane()
        .request_exposure(stale_pin.clone(), 1_011)
        .expect("request stale exposure");
    let stale = GatewayExposure::compile(
        stale_pin,
        ProviderId::Codex,
        &catalog,
        None,
        Vec::new(),
        limits,
    )
    .expect("stale exposure");
    service
        .stage_refresh(stale, ListChangeSupport::Negotiated, 1_012)
        .expect("stage stale refresh");
    service
        .control_plane()
        .request_exposure(pin('d', &profile), 1_013)
        .expect("request newer exposure");

    assert!(matches!(
        service.validate_notified_exposure_is_current(),
        Err(GatewayError::InvalidExposure(_))
    ));
    assert_eq!(service.list_tools(1_015).expect("safe tools"), original);
}

#[test]
fn unsupported_list_changes_require_reload_without_swapping_safe_set() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let limits = GatewayLimits::default();
    let initial = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("initial exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", initial, limits);
    let original = service.list_tools(1_010).unwrap();
    let empty_pin = PinnedExposure {
        revision: digest('f'),
        profile: PinnedProfile::None,
        capability_locks: None,
    };
    service
        .control_plane()
        .request_exposure(empty_pin.clone(), 1_011)
        .expect("request empty exposure");
    let empty = GatewayExposure::compile(
        empty_pin,
        ProviderId::Codex,
        &catalog,
        None,
        Vec::new(),
        limits,
    )
    .expect("empty exposure");
    assert_eq!(
        service
            .stage_refresh(empty, ListChangeSupport::Unsupported, 1_012)
            .unwrap(),
        GatewayRefreshOutcome::ReloadRequired
    );
    assert_eq!(service.list_tools(1_013).unwrap(), original);
    assert_eq!(
        service
            .control_plane()
            .status()
            .unwrap()
            .observed_exposure_revision,
        digest('e')
    );
}

#[test]
fn concurrent_and_response_limits_release_admission_on_every_terminal_path() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let limits = GatewayLimits {
        maximum_concurrent_calls: 1,
        maximum_response_bytes: 16,
        ..GatewayLimits::default()
    };
    let exposure = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", exposure, limits);
    let name = service.list_tools(1_010).unwrap()[0].name.clone();
    let mut deep_arguments = json!({});
    for _ in 0..=limits.maximum_argument_depth {
        deep_arguments = json!({"nested": deep_arguments});
    }
    assert!(matches!(
        service
            .data_plane()
            .admit_tool(&name, &deep_arguments, 1_010),
        Err(GatewayError::ArgumentsLimitExceeded)
    ));
    let mut first = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_011)
        .expect("first call");
    assert!(matches!(
        service.data_plane().admit_tool(&name, &json!({}), 1_012),
        Err(GatewayError::ConcurrencyLimitExceeded)
    ));
    assert!(matches!(
        service.data_plane().finish_tool(
            &mut first,
            &json!({"payload": "response is too long"}),
            1_013,
        ),
        Err(GatewayError::ResponseLimitExceeded)
    ));
    let mut after_error = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_014)
        .expect("admission released after response error");
    service
        .data_plane()
        .cancel_tool(&mut after_error, 1_015)
        .expect("cancel terminal path");
    assert_eq!(service.control_plane().status().unwrap().in_flight_calls, 0);
}

#[test]
fn failed_finish_preserves_permit_for_cleanup_retry() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").expect("tool source");
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let catalog = Catalog::from_records([tool.clone()]).expect("catalog");
    let profile = compile(&catalog, "tools", vec![tool.id.clone()]);
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .expect("exposure");
    let service = service(temp.path(), "workspace-a", "connection-a", exposure, limits);
    let name = service.list_tools(1_010).unwrap()[0].name.clone();
    let mut permit = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_011)
        .expect("admit call");
    let session_id = service.control_plane().status().unwrap().session_id;
    let lease_path = get_session_lease_path(temp.path(), &session_id);
    let lease = fs::read(&lease_path).expect("read lease");
    fs::remove_file(&lease_path).expect("remove lease");

    assert!(
        service
            .data_plane()
            .finish_tool(&mut permit, &json!({"ok": true}), 1_012)
            .is_err()
    );
    assert!(permit.is_active());
    fs::write(&lease_path, lease).expect("restore lease");
    service
        .data_plane()
        .finish_tool(&mut permit, &json!({"ok": true}), 1_013)
        .expect("reuse retained after plan");
    assert!(!permit.is_active());
}

#[test]
fn parallel_workspaces_keep_capability_references_and_upstreams_isolated() {
    let temp = TempDir::new();
    let skill_a_path = temp.path().join("skill-a.md");
    let skill_b_path = temp.path().join("skill-b.md");
    fs::write(&skill_a_path, "workspace A").unwrap();
    fs::write(&skill_b_path, "workspace B").unwrap();
    let skill_a = record("skill-a", CapabilityKind::Skill, &skill_a_path, 'a');
    let skill_b = record("skill-b", CapabilityKind::Skill, &skill_b_path, 'b');
    let catalog = Catalog::from_records([skill_a.clone(), skill_b.clone()]).expect("catalog");
    let profile_a = compile(&catalog, "profile-a", vec![skill_a.id.clone()]);
    let profile_b = compile(&catalog, "profile-b", vec![skill_b.id.clone()]);
    let limits = GatewayLimits::default();
    let exposure_a = GatewayExposure::compile(
        pin('a', &profile_a),
        ProviderId::Codex,
        &catalog,
        Some(&profile_a),
        Vec::new(),
        limits,
    )
    .unwrap();
    let exposure_b = GatewayExposure::compile(
        pin('b', &profile_b),
        ProviderId::Codex,
        &catalog,
        Some(&profile_b),
        Vec::new(),
        limits,
    )
    .unwrap();
    let service_a = service(
        temp.path(),
        "workspace-a",
        "connection-a",
        exposure_a,
        limits,
    );
    let service_b = service(
        temp.path(),
        "workspace-b",
        "connection-b",
        exposure_b,
        limits,
    );
    let reference_a = service_a.search_skills("", 10, 1_010).unwrap()[0]
        .reference
        .clone();
    let reference_b = service_b.search_skills("", 10, 1_010).unwrap()[0]
        .reference
        .clone();
    assert_ne!(reference_a, reference_b);
    assert!(
        service_a
            .load_skill(&reference_a, 1_011)
            .unwrap()
            .body
            .contains("A")
    );
    assert!(
        service_b
            .load_skill(&reference_b, 1_011)
            .unwrap()
            .body
            .contains("B")
    );
    assert!(matches!(
        service_a.load_skill(&reference_b, 1_012),
        Err(GatewayError::CapabilityUnavailable)
    ));
    assert!(matches!(
        service_b.load_skill(&reference_a, 1_012),
        Err(GatewayError::CapabilityUnavailable)
    ));
}

#[test]
fn gateway_hooks_are_profile_scoped_and_gate_upstream_admission() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").unwrap();
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let hook = record("before-hook", CapabilityKind::Hook, &source, 'b');
    let catalog = Catalog::from_records([tool.clone(), hook.clone()]).unwrap();
    let guarded_profile = compile(&catalog, "guarded", vec![tool.id.clone(), hook.id.clone()]);
    let handler = gateway_hook(
        ProviderId::Codex,
        "before-hook",
        HookEventFamily::BeforeTool,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &guarded_profile.digest,
    );
    let limits = GatewayLimits::default();
    let guarded = GatewayExposure::compile_with_hooks(
        pin('c', &guarded_profile),
        ProviderId::Codex,
        &catalog,
        Some(&guarded_profile),
        vec![registration(
            &tool,
            "guarded-registration",
            "guarded-server",
            "run",
            "https://example.test/mcp",
        )],
        vec![GatewayHookRegistration {
            capability_id: hook.id.clone(),
            capability_fingerprint: hook.fingerprint.clone(),
            provider: ProviderId::Codex,
            handler,
        }],
        limits,
    )
    .unwrap();
    let guarded = service(
        temp.path(),
        "workspace-guarded",
        "connection-guarded",
        guarded,
        limits,
    );
    let name = guarded.list_tools(1_010).unwrap()[0].name.clone();
    let mut permit = guarded
        .data_plane()
        .admit_tool(&name, &json!({"value": "guarded"}), 1_011)
        .unwrap();
    assert_eq!(permit.before_hook_plan().unwrap().steps().len(), 1);
    let decision = guarded
        .data_plane()
        .complete_before_hooks(
            &mut permit,
            BTreeMap::from([("before-hook".to_string(), HookActionOutcome::Deny)]),
            &[],
            |_| true,
        )
        .unwrap();
    assert_eq!(decision.decision, HookBeforeDecision::Deny);
    assert!(matches!(
        permit.upstream_arguments(),
        Err(GatewayError::HookPolicyDenied)
    ));
    guarded
        .data_plane()
        .cancel_tool(&mut permit, 1_012)
        .unwrap();

    let open_profile = compile(&catalog, "open", vec![tool.id.clone()]);
    let open = GatewayExposure::compile(
        pin('d', &open_profile),
        ProviderId::Codex,
        &catalog,
        Some(&open_profile),
        vec![registration(
            &tool,
            "open-registration",
            "open-server",
            "run",
            "https://example.test/mcp",
        )],
        limits,
    )
    .unwrap();
    let open = service(
        temp.path(),
        "workspace-open",
        "connection-open",
        open,
        limits,
    );
    let open_name = open.list_tools(1_010).unwrap()[0].name.clone();
    let mut open_permit = open
        .data_plane()
        .admit_tool(&open_name, &json!({"value": "open"}), 1_011)
        .unwrap();
    assert!(open_permit.before_hook_plan().is_none());
    assert_eq!(
        open_permit.upstream_arguments().unwrap(),
        &json!({"value": "open"})
    );
    open.data_plane()
        .finish_tool(&mut open_permit, &json!({"ok": true}), 1_012)
        .unwrap();
    assert_eq!(guarded.control_plane().status().unwrap().in_flight_calls, 0);
    assert_eq!(open.control_plane().status().unwrap().in_flight_calls, 0);
}

#[cfg(unix)]
#[test]
fn after_hook_completion_consumes_exact_planned_handler_set() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").unwrap();
    let executable = temp.path().join("after-hook");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let hook = record("after-hook", CapabilityKind::Hook, &source, 'b');
    let catalog = Catalog::from_records([tool.clone(), hook.clone()]).unwrap();
    let profile = compile(&catalog, "after", vec![tool.id.clone(), hook.id.clone()]);
    let handler = reviewed_gateway_hook_action(
        ProviderId::Codex,
        "after-hook",
        HookEventFamily::AfterToolSuccess,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        HookAction::structured_command(
            &executable,
            Vec::new(),
            temp.path(),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap(),
        &profile.digest,
    );
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile_with_hooks(
        pin('d', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        vec![GatewayHookRegistration {
            capability_id: hook.id.clone(),
            capability_fingerprint: hook.fingerprint.clone(),
            provider: ProviderId::Codex,
            handler,
        }],
        limits,
    )
    .unwrap();
    let service = service(temp.path(), "workspace", "connection", exposure, limits);
    let name = service.list_tools(1_010).unwrap()[0].name.clone();
    let mut permit = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_011)
        .unwrap();
    let response = json!({"value": "original"});
    let plan = service
        .data_plane()
        .plan_after_hooks(&mut permit, true, &response)
        .unwrap();
    assert_eq!(plan.steps().len(), 1);

    fs::write(&executable, "#!/bin/sh\nexit 9\n").unwrap();
    let outcomes = BTreeMap::from([("after-hook".to_string(), HookActionOutcome::Continue)]);
    assert!(matches!(
        service.data_plane().finish_tool_with_hooks(
            &mut permit,
            true,
            &json!({"value": "different"}),
            outcomes.clone(),
            1_012,
        ),
        Err(GatewayError::HookDispatchIncomplete)
    ));
    assert!(permit.is_active());

    let after = service
        .data_plane()
        .finish_tool_with_hooks(&mut permit, true, &response, outcomes, 1_013)
        .unwrap();
    assert_eq!(after.result, response);
    assert_eq!(after.ancestry, ["after-hook"]);
    assert!(after.failures.is_empty());
    assert!(!permit.is_active());
}

#[test]
fn gateway_after_hook_result_requires_explicit_rewrite_approval() {
    let temp = TempDir::new();
    let source = temp.path().join("mcp.json");
    fs::write(&source, "{}").unwrap();
    let tool = record("tool", CapabilityKind::McpTool, &source, 'a');
    let hook = record("after-hook", CapabilityKind::Hook, &source, 'b');
    let catalog = Catalog::from_records([tool.clone(), hook.clone()]).unwrap();
    let profile = compile(&catalog, "after", vec![tool.id.clone(), hook.id.clone()]);
    let handler = gateway_hook(
        ProviderId::Codex,
        "after-hook",
        HookEventFamily::AfterToolSuccess,
        HookFailurePolicy::ContinueDegraded,
        HookTransformCapabilities {
            argument_rewrite: false,
            result_modification: true,
            context_injection: false,
        },
        &profile.digest,
    );
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile_with_hooks(
        pin('e', &profile),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration(
            &tool,
            "registration",
            "server",
            "run",
            "https://example.test/mcp",
        )],
        vec![GatewayHookRegistration {
            capability_id: hook.id.clone(),
            capability_fingerprint: hook.fingerprint.clone(),
            provider: ProviderId::Codex,
            handler,
        }],
        limits,
    )
    .unwrap();
    let service = service(temp.path(), "workspace", "connection", exposure, limits);
    let name = service.list_tools(1_010).unwrap()[0].name.clone();
    let mut permit = service
        .data_plane()
        .admit_tool(&name, &json!({}), 1_011)
        .unwrap();
    let plan = service
        .data_plane()
        .plan_after_hooks(&mut permit, true, &json!({"value": "original"}))
        .unwrap();
    assert_eq!(plan.steps().len(), 1);
    let after = service
        .data_plane()
        .finish_tool_with_hooks(
            &mut permit,
            true,
            &json!({"value": "original"}),
            BTreeMap::from([(
                "after-hook".to_string(),
                HookActionOutcome::ReplaceResult(json!({"value": "replaced"})),
            )]),
            1_012,
        )
        .unwrap();
    assert_eq!(after.result, json!({"value": "original"}));
    assert!(after.failures.iter().any(|failure| {
        failure.reason == unpin_core::hooks::HookFailureReason::RewriteApprovalRequired
    }));
    assert_eq!(after.ancestry, ["after-hook"]);
    assert!(!permit.is_active());
}
