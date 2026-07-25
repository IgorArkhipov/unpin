use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{CallToolRequestParams, JsonObject},
    service::{MaybeSendFuture, NotificationContext},
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use unpin_cli::mcp_runtime::{
    BoundBearerToken, GatewayMcpServer, GatewayRuntimeError, GatewayRuntimeTimeouts,
    McpUpstreamPool, NoGatewayCredentials, notify_list_changed,
};
use unpin_core::{
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ProviderView,
    },
    discovery::DiscoveryLayer,
    gateway::{
        GatewayControlPlane, GatewayExposure, GatewayLimits, GatewayRefreshOutcome,
        ListChangeSupport, UpstreamIdentity, UpstreamToolDescriptor, UpstreamToolRegistration,
    },
    profiles::{
        PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope, compile_profile,
    },
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
        PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
    },
};

fn fixtures_root() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates directory")
        .join("unpin-core")
        .join("tests")
        .join("fixtures")
        .to_string_lossy()
        .into_owned()
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("unix timestamp")
}

fn skill_gateway(temp: &TempDir) -> Arc<unpin_core::gateway::GatewayService> {
    let root = fs::canonicalize(temp.path()).expect("canonical temporary directory");
    let skill_path = root.join("SKILL.md");
    fs::write(&skill_path, "test").expect("skill body");
    let capability_id = CapabilityId::new("skill.review").expect("capability id");
    let record = CatalogRecord {
        id: capability_id.clone(),
        kind: CapabilityKind::Skill,
        display_name: "peer-review".to_string(),
        origin: CanonicalOrigin {
            canonical_key: "review-origin".to_string(),
            source_path: skill_path.to_string_lossy().into_owned(),
            state_path: skill_path.to_string_lossy().into_owned(),
            scope: CapabilityScope::Repository,
            source_fingerprint: Some(
                "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    .to_string(),
            ),
        },
        ownership: CapabilityOwnership::User,
        fingerprint: digest('a'),
        lifecycle: CapabilityLifecycle::discovered(true),
        state_evidence: CapabilityStateEvidence {
            observation: "runtime-test".to_string(),
            observed_enabled: true,
        },
        trust_requirements: CapabilityTrustRequirements::default(),
        provider_views: vec![ProviderView {
            provider: ProviderId::Codex,
            discovery_id: "codex:skill:review".to_string(),
            layer: DiscoveryLayer::Project,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: skill_path.to_string_lossy().into_owned(),
            state_path: skill_path.to_string_lossy().into_owned(),
            source_fingerprint: None,
        }],
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    };
    let catalog = Catalog::from_records([record]).expect("catalog");
    let profile = compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: "review".to_string(),
            display_name: "Review".to_string(),
            description: None,
            members: vec![capability_id],
            provider_members: BTreeMap::new(),
        },
        &catalog,
        ProfileSourceScope::Session,
    )
    .expect("profile");
    let pinned = PinnedExposure {
        revision: digest('e'),
        profile: PinnedProfile::Profile {
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.digest.clone(),
            origin_scope: profile.origin.scope,
            definition_digest: profile.origin.definition_digest.clone(),
        },
        capability_locks: None,
    };
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pinned.clone(),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        Vec::new(),
        limits,
    )
    .expect("exposure");
    let now = now_unix();
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x53; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "workspace".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: pinned,
        process: ProcessEvidence {
            pid: std::process::id(),
            start_marker: "runtime-test".to_string(),
        },
        connection_scope_id: "runtime-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["runtime-test-resource".to_string()]),
        lease_expires_at_unix: now + 600,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "runtime-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = manager
        .prepare_bootstrap(request, now)
        .expect("prepare bootstrap");
    let session = manager
        .claim_bootstrap(&authority, &claim, now)
        .expect("claim bootstrap");
    let control =
        GatewayControlPlane::new(manager, session.handle, limits.maximum_concurrent_calls)
            .expect("control plane");
    Arc::new(
        unpin_core::gateway::GatewayService::new(control, exposure, limits)
            .expect("gateway service"),
    )
}

fn fixture_upstream_identity(state: &TempDir) -> UpstreamIdentity {
    let home = state.path().join("home");
    fs::create_dir_all(&home).expect("fixture home");
    UpstreamIdentity::stdio(
        "unpin-fixture",
        env!("CARGO_BIN_EXE_unpin"),
        vec![
            "mcp".to_string(),
            "--home-root".to_string(),
            home.to_string_lossy().into_owned(),
            "--fixture-root".to_string(),
            fixtures_root(),
            "--app-state-root".to_string(),
            state.path().to_string_lossy().into_owned(),
        ],
    )
    .expect("stdio identity")
}

fn tool_gateway(
    temp: &TempDir,
    identity: UpstreamIdentity,
) -> Arc<unpin_core::gateway::GatewayService> {
    let root = fs::canonicalize(temp.path()).expect("canonical temporary directory");
    let source_path = root.join("mcp.json");
    fs::write(&source_path, "{}").expect("tool source");
    let capability_id = CapabilityId::new("mcp-tool.doctor").expect("capability id");
    let record = CatalogRecord {
        id: capability_id.clone(),
        kind: CapabilityKind::McpTool,
        display_name: "doctor".to_string(),
        origin: CanonicalOrigin {
            canonical_key: "doctor-origin".to_string(),
            source_path: source_path.to_string_lossy().into_owned(),
            state_path: source_path.to_string_lossy().into_owned(),
            scope: CapabilityScope::Repository,
            source_fingerprint: None,
        },
        ownership: CapabilityOwnership::User,
        fingerprint: digest('b'),
        lifecycle: CapabilityLifecycle::discovered(true),
        state_evidence: CapabilityStateEvidence {
            observation: "runtime-test".to_string(),
            observed_enabled: true,
        },
        trust_requirements: CapabilityTrustRequirements::default(),
        provider_views: vec![ProviderView {
            provider: ProviderId::Codex,
            discovery_id: "codex:mcp-tool:doctor".to_string(),
            layer: DiscoveryLayer::Project,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: source_path.to_string_lossy().into_owned(),
            state_path: source_path.to_string_lossy().into_owned(),
            source_fingerprint: None,
        }],
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    };
    let catalog = Catalog::from_records([record.clone()]).expect("catalog");
    let profile = compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: "doctor".to_string(),
            display_name: "Doctor".to_string(),
            description: None,
            members: vec![capability_id],
            provider_members: BTreeMap::new(),
        },
        &catalog,
        ProfileSourceScope::Session,
    )
    .expect("profile");
    let pinned = PinnedExposure {
        revision: digest('f'),
        profile: PinnedProfile::Profile {
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.digest.clone(),
            origin_scope: profile.origin.scope,
            definition_digest: profile.origin.definition_digest.clone(),
        },
        capability_locks: None,
    };
    let registration = UpstreamToolRegistration {
        registration_id: "doctor-registration".to_string(),
        capability_id: record.id.clone(),
        capability_fingerprint: record.fingerprint.clone(),
        provider: ProviderId::Codex,
        identity,
        credential: None,
        descriptor: UpstreamToolDescriptor {
            name: "unpin_run_doctor".to_string(),
            title: Some("Unpin doctor".to_string()),
            description: Some("Run fixture doctor".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false
            }),
            output_schema: Some(serde_json::json!({"type": "object"})),
            annotations: Some(serde_json::json!({
                "readOnlyHint": true,
                "openWorldHint": false
            })),
            execution: Some(serde_json::json!({"taskSupport": "optional"})),
        },
    };
    let limits = GatewayLimits::default();
    let exposure = GatewayExposure::compile(
        pinned.clone(),
        ProviderId::Codex,
        &catalog,
        Some(&profile),
        vec![registration],
        limits,
    )
    .expect("exposure");
    let now = now_unix();
    let manager = SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x53; 32]));
    let request = BootstrapRequest {
        provider: ProviderId::Codex,
        repository_key: "repository".to_string(),
        workspace_key: "tool-workspace".to_string(),
        workspace_revision: Some(digest('1')),
        exposure: pinned,
        process: ProcessEvidence {
            pid: std::process::id(),
            start_marker: "runtime-tool-test".to_string(),
        },
        connection_scope_id: "runtime-tool-connection".to_string(),
        isolation: IsolationLevel::Strict,
        coverage: CoverageLevel::VerifiedMasked,
        protected_resources: BTreeSet::from(["runtime-tool-resource".to_string()]),
        lease_expires_at_unix: now + 600,
    };
    let claim = ConnectionClaim {
        connection_owner_id: "runtime-tool-owner".to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        process: request.process.clone(),
        connection_scope_id: request.connection_scope_id.clone(),
    };
    let authority = manager
        .prepare_bootstrap(request, now)
        .expect("prepare bootstrap");
    let session = manager
        .claim_bootstrap(&authority, &claim, now)
        .expect("claim bootstrap");
    let control =
        GatewayControlPlane::new(manager, session.handle, limits.maximum_concurrent_calls)
            .expect("control plane");
    Arc::new(
        unpin_core::gateway::GatewayService::new(control, exposure, limits)
            .expect("gateway service"),
    )
}

#[derive(Clone)]
enum HttpFixtureMode {
    Success,
    Reject {
        status: u16,
        reason: &'static str,
        body: String,
    },
    SlowCall(Duration),
}

struct HttpMcpFixture {
    endpoint: String,
    authorization_headers: Arc<Mutex<Vec<Option<String>>>>,
    tool_calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Default)]
struct ListChangeClient {
    count: Arc<AtomicUsize>,
    notified: Arc<Notify>,
}

impl ClientHandler for ListChangeClient {
    fn on_tool_list_changed(
        &self,
        _context: NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + MaybeSendFuture + '_ {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.notified.notify_one();
        std::future::ready(())
    }
}

async fn spawn_http_mcp_fixture(mode: HttpFixtureMode) -> HttpMcpFixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("HTTP fixture listener");
    let address = listener.local_addr().expect("HTTP fixture address");
    let authorization_headers = Arc::new(Mutex::new(Vec::new()));
    let tool_calls = Arc::new(AtomicUsize::new(0));
    let fixture_authorization_headers = Arc::clone(&authorization_headers);
    let fixture_tool_calls = Arc::clone(&tool_calls);
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.expect("HTTP fixture accept");
            let mode = mode.clone();
            let authorization_headers = Arc::clone(&fixture_authorization_headers);
            let tool_calls = Arc::clone(&fixture_tool_calls);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let header_end = loop {
                    let mut chunk = [0_u8; 4096];
                    let read = socket.read(&mut chunk).await.expect("read HTTP request");
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(position) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                    assert!(request.len() < 1024 * 1024, "HTTP fixture header limit");
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let authorization = headers.lines().find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_string())
                    })
                });
                authorization_headers
                    .lock()
                    .expect("authorization fixture lock")
                    .push(authorization);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().expect("content length"))
                        })
                    })
                    .unwrap_or_default();
                while request.len() - header_end < content_length {
                    let mut chunk = [0_u8; 4096];
                    let read = socket.read(&mut chunk).await.expect("read HTTP body");
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                let message: serde_json::Value =
                    serde_json::from_slice(&request[header_end..header_end + content_length])
                        .expect("HTTP fixture JSON");
                if let HttpFixtureMode::Reject {
                    status,
                    reason,
                    body,
                } = &mode
                {
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    return;
                }
                let Some(request_id) = message.get("id").cloned() else {
                    socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("write accepted response");
                    return;
                };
                let method = message.get("method").and_then(serde_json::Value::as_str);
                let result = match method {
                    Some("initialize") => serde_json::json!({
                        "protocolVersion": message["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-fixture", "version": "1"}
                    }),
                    Some("tools/call") => {
                        tool_calls.fetch_add(1, Ordering::SeqCst);
                        if let HttpFixtureMode::SlowCall(delay) = &mode {
                            tokio::time::sleep(*delay).await;
                        }
                        serde_json::json!({
                            "content": [{"type": "text", "text": "ok"}],
                            "structuredContent": {"transport": "streamable-http"}
                        })
                    }
                    _ => serde_json::json!({}),
                };
                let body = serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result
                }))
                .expect("HTTP fixture response");
                if socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .is_ok()
                {
                    let _ = socket.write_all(&body).await;
                }
            });
        }
    });
    HttpMcpFixture {
        endpoint: format!("http://{address}/mcp"),
        authorization_headers,
        tool_calls,
        task,
    }
}

#[tokio::test]
async fn stdio_pool_calls_real_child_mcp_server() {
    let state = TempDir::new().expect("temporary state");
    let identity = fixture_upstream_identity(&state);
    let result = McpUpstreamPool::default()
        .call(
            &identity,
            None,
            None,
            "unpin_run_doctor",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(15),
                call: Duration::from_secs(15),
            },
        )
        .await
        .expect("child MCP call");

    assert_eq!(
        result
            .structured_content
            .as_ref()
            .and_then(|value| value.get("status"))
            .and_then(serde_json::Value::as_str),
        Some("ok")
    );
    assert_ne!(result.is_error, Some(true));
}

#[tokio::test]
async fn stdio_handshake_is_bounded() {
    let temp = TempDir::new().expect("temporary directory");
    let sleeper = temp.path().join("slow-mcp");
    fs::write(&sleeper, "#!/bin/sh\n/bin/sleep 5\n").expect("slow fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sleeper, fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
    let identity = UpstreamIdentity::stdio("slow", &sleeper, Vec::new()).expect("slow identity");
    let result = McpUpstreamPool::default()
        .call(
            &identity,
            None,
            None,
            "never",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_millis(50),
                call: Duration::from_millis(50),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(GatewayRuntimeError::UpstreamConnectTimedOut)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn stdio_launch_executes_verified_descriptor_after_path_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let server = temp.path().join("reviewed-server");
    let replacement = temp.path().join("replacement-server");
    let interpreter = temp.path().join("replacing-interpreter");
    let marker = temp.path().join("executed.txt");
    fs::write(
        &interpreter,
        "#!/bin/sh\nprintf wrapper > \"$4\"\nmv \"$3\" \"$2\"\n/bin/sh \"$1\" \"$4\"\nprintf -- \"-status-$?\" >> \"$4\"\n",
    )
    .expect("write replacing interpreter");
    fs::write(
        &server,
        format!(
            "#!{}\nprintf benign > \"$1\"\nexit 0\n",
            interpreter.display()
        ),
    )
    .expect("write reviewed server");
    fs::write(
        &replacement,
        "#!/bin/sh\nprintf malicious > \"$1\"\nexit 0\n",
    )
    .expect("write replacement server");
    for executable in [&interpreter, &server, &replacement] {
        fs::set_permissions(executable, fs::Permissions::from_mode(0o700))
            .expect("make fixture executable");
    }
    let identity = UpstreamIdentity::stdio(
        "replacement-race",
        &server,
        vec![
            server.to_string_lossy().into_owned(),
            replacement.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ],
    )
    .expect("review stdio chain");

    let result = McpUpstreamPool::default()
        .call(
            &identity,
            None,
            None,
            "never",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(2),
                call: Duration::from_secs(2),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(GatewayRuntimeError::UpstreamConnectFailed)
    ));
    assert_eq!(
        fs::read_to_string(&marker).expect("execution marker"),
        "benign-status-0"
    );
    assert!(
        fs::read_to_string(&server)
            .expect("replacement installed")
            .contains("malicious")
    );
}

#[tokio::test]
async fn streamable_http_pool_calls_bounded_local_server() {
    let fixture = spawn_http_mcp_fixture(HttpFixtureMode::Success).await;
    let identity = UpstreamIdentity::streamable_http("http-fixture", &fixture.endpoint)
        .expect("HTTP upstream identity");

    let result = McpUpstreamPool::default()
        .call(
            &identity,
            None,
            None,
            "environment",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(5),
                call: Duration::from_secs(5),
            },
        )
        .await
        .expect("HTTP MCP call");
    fixture.task.abort();

    assert_eq!(
        result.structured_content.as_ref().unwrap()["transport"],
        "streamable-http"
    );
}

#[tokio::test]
async fn streamable_http_pool_authenticates_without_exposing_resolver_secret() {
    let fixture = spawn_http_mcp_fixture(HttpFixtureMode::Success).await;
    let identity = UpstreamIdentity::streamable_http("authenticated", &fixture.endpoint)
        .expect("authenticated upstream identity");
    let secret = "fixture-bearer-secret";
    let token = BoundBearerToken::new("credential", &identity, secret).expect("bound token");
    let token_debug = format!("{token:?}");
    assert!(token_debug.contains("[REDACTED]"));
    assert!(!token_debug.contains(secret));

    let result = McpUpstreamPool::default()
        .call(
            &identity,
            Some("credential"),
            Some(token),
            "environment",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(5),
                call: Duration::from_secs(5),
            },
        )
        .await
        .expect("authenticated HTTP MCP call");
    fixture.task.abort();

    assert_eq!(
        result.structured_content.as_ref().unwrap()["transport"],
        "streamable-http"
    );
    assert_eq!(fixture.tool_calls.load(Ordering::SeqCst), 1);
    let headers = fixture
        .authorization_headers
        .lock()
        .expect("authorization fixture lock");
    assert!(!headers.is_empty());
    assert!(
        headers
            .iter()
            .all(|header| header.as_deref() == Some("Bearer fixture-bearer-secret"))
    );
}

#[tokio::test]
async fn streamable_http_authentication_failures_are_redacted() {
    for (status, reason) in [(401, "Unauthorized"), (403, "Forbidden")] {
        let secret = format!("rejected-secret-{status}");
        let fixture = spawn_http_mcp_fixture(HttpFixtureMode::Reject {
            status,
            reason,
            body: format!("server rejected {secret}"),
        })
        .await;
        let identity = UpstreamIdentity::streamable_http("authenticated", &fixture.endpoint)
            .expect("authenticated upstream identity");
        let token =
            BoundBearerToken::new("credential", &identity, secret.clone()).expect("bound token");

        let error = match McpUpstreamPool::default()
            .call(
                &identity,
                Some("credential"),
                Some(token),
                "environment",
                JsonObject::new(),
                GatewayRuntimeTimeouts {
                    connect: Duration::from_secs(5),
                    call: Duration::from_secs(5),
                },
            )
            .await
        {
            Ok(_) => panic!("HTTP {status} must reject MCP connection"),
            Err(error) => error,
        };
        fixture.task.abort();

        assert!(matches!(&error, GatewayRuntimeError::UpstreamConnectFailed));
        let rendered = format!("{error:?}: {error}");
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains("server rejected"));
        let headers = fixture
            .authorization_headers
            .lock()
            .expect("authorization fixture lock");
        assert!(!headers.is_empty());
        let expected_header = format!("Bearer {secret}");
        assert!(
            headers
                .iter()
                .all(|header| header.as_deref() == Some(expected_header.as_str()))
        );
    }
}

#[tokio::test]
async fn bearer_token_cannot_cross_upstream_identity() {
    let identity_a = UpstreamIdentity::streamable_http("server", "https://a.example/mcp").unwrap();
    let identity_b = UpstreamIdentity::streamable_http("server", "https://b.example/mcp").unwrap();
    let token = BoundBearerToken::new("token-a", &identity_a, "secret").unwrap();
    let result = McpUpstreamPool::default()
        .call(
            &identity_b,
            Some("token-a"),
            Some(token),
            "never",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_millis(50),
                call: Duration::from_millis(50),
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(GatewayRuntimeError::CredentialUnavailable)
    ));
}

#[tokio::test]
async fn stdio_child_receives_only_curated_environment() {
    let temp = TempDir::new().expect("temporary directory");
    let script = temp.path().join("environment_mcp.py");
    fs::write(
        &script,
        r#"import json
import os
import sys

for raw in sys.stdin:
    request = json.loads(raw)
    method = request.get("method")
    request_id = request.get("id")
    if request_id is None:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "environment-fixture", "version": "1"},
        }
    elif method == "tools/call":
        forbidden = sys.argv[1]
        result = {
            "content": [{"type": "text", "text": "environment"}],
            "structuredContent": {
                "homePresent": "HOME" in os.environ,
                "pathPresent": "PATH" in os.environ,
                "forbiddenPresent": forbidden in os.environ,
            },
        }
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)
"#,
    )
    .expect("write Python MCP fixture");
    let python = [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
    ]
    .into_iter()
    .filter_map(|path| fs::canonicalize(path).ok())
    .find(|path| path.is_file())
    .expect("Python 3 executable");
    let forbidden = ["USER", "SHELL", "TERM", "SSH_AUTH_SOCK", "CODEX_THREAD_ID"]
        .into_iter()
        .find(|key| std::env::var_os(key).is_some())
        .map(str::to_string)
        .or_else(|| {
            std::env::vars_os()
                .map(|(key, _)| key.to_string_lossy().into_owned())
                .find(|key| !["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"].contains(&key.as_str()))
        })
        .expect("ambient variable outside child allowlist");
    let identity = UpstreamIdentity::stdio(
        "environment-fixture",
        python,
        vec![script.to_string_lossy().into_owned(), forbidden],
    )
    .expect("fixture identity");

    let result = McpUpstreamPool::default()
        .call(
            &identity,
            None,
            None,
            "environment",
            JsonObject::new(),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(5),
                call: Duration::from_secs(5),
            },
        )
        .await
        .expect("environment fixture call");
    let structured = result.structured_content.expect("structured environment");

    assert_eq!(
        structured["homePresent"],
        std::env::var_os("HOME").is_some()
    );
    assert_eq!(
        structured["pathPresent"],
        std::env::var_os("PATH").is_some()
    );
    assert_eq!(structured["forbiddenPresent"], false);
}

#[tokio::test]
async fn gateway_server_exposes_compact_control_surface_and_lazy_skill_body() {
    let temp = TempDir::new().expect("temporary directory");
    let gateway = skill_gateway(&temp);
    let server = GatewayMcpServer::new(
        gateway,
        Arc::new(NoGatewayCredentials),
        GatewayRuntimeTimeouts::default(),
    );
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let server_start = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = ().serve(client_io).await.expect("connect gateway client");
    let mut server = server_start
        .await
        .expect("gateway server task")
        .expect("serve gateway");

    let tools = tokio::time::timeout(Duration::from_secs(5), client.list_all_tools())
        .await
        .expect("list gateway tools timeout")
        .expect("list gateway tools");
    let names = tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "unpin_get_session_status",
            "unpin_load_skill",
            "unpin_search_skills",
        ])
    );

    let invalid_search = client
        .call_tool(
            CallToolRequestParams::new("unpin_search_skills").with_arguments(
                serde_json::from_value(serde_json::json!({"query": 7, "extra": true})).unwrap(),
            ),
        )
        .await;
    assert!(invalid_search.is_err());

    let search = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(
            CallToolRequestParams::new("unpin_search_skills").with_arguments(
                serde_json::from_value(serde_json::json!({"query": "review"})).unwrap(),
            ),
        ),
    )
    .await
    .expect("search skills timeout")
    .expect("search skills");
    let skill = &search.structured_content.as_ref().unwrap()["skills"][0];
    assert_eq!(skill["name"], "peer-review");
    assert!(skill.get("body").is_none());
    let reference = skill["reference"].as_str().unwrap();
    let load = tokio::time::timeout(
        Duration::from_secs(5),
        client.call_tool(
            CallToolRequestParams::new("unpin_load_skill").with_arguments(
                serde_json::from_value(serde_json::json!({"reference": reference})).unwrap(),
            ),
        ),
    )
    .await
    .expect("load skill timeout")
    .expect("load skill");
    assert_eq!(load.structured_content.as_ref().unwrap()["body"], "test");

    client
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close client");
    server
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close server");
}

#[tokio::test]
async fn gateway_projects_and_dispatches_upstream_tool_end_to_end() {
    let temp = TempDir::new().expect("temporary directory");
    let identity = fixture_upstream_identity(&temp);
    let gateway = tool_gateway(&temp, identity);
    let server = GatewayMcpServer::new(
        gateway,
        Arc::new(NoGatewayCredentials),
        GatewayRuntimeTimeouts {
            connect: Duration::from_secs(15),
            call: Duration::from_secs(15),
        },
    );
    let (client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
    let server_start = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = ().serve(client_io).await.expect("connect gateway client");
    let mut server = server_start
        .await
        .expect("gateway server task")
        .expect("serve gateway");

    let tools = client.list_all_tools().await.expect("list projected tools");
    let projected = tools
        .iter()
        .find(|tool| tool.name.contains("unpin_run_doctor"))
        .expect("projected doctor tool");
    let projected_json = serde_json::to_value(projected).expect("projected tool JSON");
    assert_eq!(projected_json["title"], "Unpin doctor");
    assert_eq!(projected_json["outputSchema"]["type"], "object");
    assert_eq!(projected_json["annotations"]["readOnlyHint"], true);
    // rmcp 3's draft-aligned Tool model no longer serializes the legacy
    // execution.taskSupport field.
    assert!(projected_json.get("execution").is_none());

    let result = client
        .call_tool(CallToolRequestParams::new(projected.name.clone()))
        .await
        .expect("call projected tool");
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .and_then(|value| value.get("status"))
            .and_then(serde_json::Value::as_str),
        Some("ok")
    );
    assert_ne!(result.is_error, Some(true));

    let status = client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("session status");
    assert_eq!(
        status.structured_content.as_ref().unwrap()["inFlightCalls"],
        0
    );

    client
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close client");
    server
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close server");
}

#[tokio::test]
async fn admitted_timeout_is_unknown_single_attempt_and_releases_permit() {
    let fixture =
        spawn_http_mcp_fixture(HttpFixtureMode::SlowCall(Duration::from_millis(250))).await;
    let identity = UpstreamIdentity::streamable_http("slow-tool", &fixture.endpoint)
        .expect("slow upstream identity");
    let temp = TempDir::new().expect("temporary directory");
    let gateway = tool_gateway(&temp, identity);
    let server = GatewayMcpServer::new(
        Arc::clone(&gateway),
        Arc::new(NoGatewayCredentials),
        GatewayRuntimeTimeouts {
            connect: Duration::from_secs(5),
            call: Duration::from_millis(50),
        },
    );
    let (client_io, server_io) = tokio::io::duplex(4 * 1024 * 1024);
    let server_start = tokio::spawn(async move { server.serve(server_io).await });
    let mut client = ().serve(client_io).await.expect("connect gateway client");
    let mut server = server_start
        .await
        .expect("gateway server task")
        .expect("serve gateway");
    let projected_name = client
        .list_all_tools()
        .await
        .expect("list projected tools")
        .into_iter()
        .find(|tool| tool.name.contains("unpin_run_doctor"))
        .expect("projected doctor tool")
        .name;

    let result = client
        .call_tool(CallToolRequestParams::new(projected_name))
        .await
        .expect("timeout is a tool result, not protocol failure");
    let encoded = serde_json::to_value(&result).expect("timeout result JSON");
    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        encoded["content"][0]["text"],
        "upstream call timed out; completion status is unknown"
    );
    assert_eq!(fixture.tool_calls.load(Ordering::SeqCst), 1);

    let status = client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("session status after timeout");
    assert_eq!(
        status.structured_content.as_ref().unwrap()["inFlightCalls"],
        0
    );

    fixture.task.abort();
    client
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close client");
    server
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close server");
}

#[tokio::test]
async fn list_changed_is_connection_local_and_status_tracks_observation() {
    let temp = TempDir::new().expect("temporary directory");
    let identity = fixture_upstream_identity(&temp);
    let gateway = tool_gateway(&temp, identity);
    let timeouts = GatewayRuntimeTimeouts::default();
    let server = GatewayMcpServer::new(
        Arc::clone(&gateway),
        Arc::new(NoGatewayCredentials),
        timeouts,
    );
    let first_server = server.clone();
    let second_server = server;
    let first_observer = ListChangeClient::default();
    let second_observer = ListChangeClient::default();
    let (first_client_io, first_server_io) = tokio::io::duplex(1024 * 1024);
    let (second_client_io, second_server_io) = tokio::io::duplex(1024 * 1024);
    let first_server_start = tokio::spawn(async move { first_server.serve(first_server_io).await });
    let second_server_start =
        tokio::spawn(async move { second_server.serve(second_server_io).await });
    let mut first_client = first_observer
        .clone()
        .serve(first_client_io)
        .await
        .expect("connect first client");
    let mut second_client = second_observer
        .clone()
        .serve(second_client_io)
        .await
        .expect("connect second client");
    let mut first_running = first_server_start
        .await
        .expect("first server task")
        .expect("serve first connection");
    let mut second_running = second_server_start
        .await
        .expect("second server task")
        .expect("serve second connection");

    let empty_pin = PinnedExposure {
        revision: digest('0'),
        profile: PinnedProfile::None,
        capability_locks: None,
    };
    gateway
        .control_plane()
        .request_exposure(empty_pin.clone(), now_unix())
        .expect("request empty exposure");
    let empty_catalog =
        Catalog::from_records(std::iter::empty::<CatalogRecord>()).expect("empty catalog");
    let empty_exposure = GatewayExposure::compile(
        empty_pin,
        ProviderId::Codex,
        &empty_catalog,
        None,
        Vec::new(),
        GatewayLimits::default(),
    )
    .expect("empty exposure");
    assert_eq!(
        gateway
            .stage_refresh(empty_exposure, ListChangeSupport::Negotiated, now_unix())
            .expect("stage negotiated refresh"),
        GatewayRefreshOutcome::NotificationRequired
    );

    let before = first_client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("status before notification");
    assert_eq!(
        before.structured_content.as_ref().unwrap()["liveStatus"],
        "configured"
    );

    notify_list_changed(&first_running)
        .await
        .expect("send list change notification");
    tokio::time::timeout(Duration::from_secs(2), first_observer.notified.notified())
        .await
        .expect("first client notification timeout");
    assert_eq!(first_observer.count.load(Ordering::SeqCst), 1);
    assert_eq!(second_observer.count.load(Ordering::SeqCst), 0);

    let sent = first_client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("status after notification");
    assert_eq!(
        sent.structured_content.as_ref().unwrap()["liveStatus"],
        "configured"
    );
    let second_connection_status = second_client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("second connection status after first notification");
    assert_eq!(
        second_connection_status
            .structured_content
            .as_ref()
            .unwrap()["liveStatus"],
        "configured"
    );
    let refreshed = first_client
        .list_all_tools()
        .await
        .expect("observe refreshed tool list");
    assert_eq!(refreshed.len(), 3);
    let observed = first_client
        .call_tool(CallToolRequestParams::new("unpin_get_session_status"))
        .await
        .expect("status after list observation");
    assert_eq!(
        observed.structured_content.as_ref().unwrap()["liveStatus"],
        "observed-refresh"
    );
    assert_eq!(second_observer.count.load(Ordering::SeqCst), 0);

    first_client
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close first client");
    second_client
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close second client");
    first_running
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close first server");
    second_running
        .close_with_timeout(Duration::from_secs(2))
        .await
        .expect("close second server");
}
