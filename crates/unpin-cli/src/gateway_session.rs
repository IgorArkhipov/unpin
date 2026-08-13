use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

use unpin_core::gateway::{GatewayError, GatewayService};
use unpin_core::sessions::{ProcessEvidence, SessionAuthorityKey};

use unpin_cli::mcp_runtime::GatewayRuntimeError;

#[cfg(unix)]
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
#[cfg(unix)]
use unpin_cli::mcp_runtime::{
    GatewayCredentialResolver, GatewayHookAuthorizationSource, GatewayMcpServer,
    GatewayPrimaryNotifier, GatewayRuntimeTimeouts, serve_gateway_io,
};

pub(crate) struct GatewaySessionRuntime {
    gateway: Arc<GatewayService>,
    socket_directory: PathBuf,
    socket_path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<(), GatewaySessionError>>>,
}

const GATEWAY_TRANSPORT_AUTHENTICATION_VERSION: u32 = 1;
const GATEWAY_TRANSPORT_AUTHENTICATION_TAG_ENV: &str = "UNPIN_GATEWAY_AUTHENTICATION_TAG";
const GATEWAY_TRANSPORT_HANDSHAKE_MAGIC: &[u8] = b"UNPIN-GATEWAY-AUTH/1\0";
const GATEWAY_TRANSPORT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GATEWAY_TRANSPORT_MAX_TAG_BYTES: usize = 128;

/// Derive the transport capability from the session authority and the exact
/// launched process generation. The resulting tag is passed only through the
/// child environment; it is intentionally absent from launch-control and
/// overlay JSON so it cannot become JSON evidence or a log field.
pub(crate) fn gateway_transport_authentication_tag(
    authority_key: &SessionAuthorityKey,
    session_id: &str,
    process: &ProcessEvidence,
    socket_path: &Path,
) -> Result<String, String> {
    let binding_socket = std::fs::canonicalize(socket_path)
        .map_err(|_| "gateway transport socket could not be canonicalized".to_string())?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "version": GATEWAY_TRANSPORT_AUTHENTICATION_VERSION,
        "sessionId": session_id,
        "process": process,
        "socket": binding_socket,
    }))
    .map_err(|_| "gateway transport binding could not be encoded".to_string())?;
    authority_key
        .authenticate_launch_control(&payload)
        .map_err(|_| "gateway transport binding could not be authenticated".to_string())
}

fn gateway_transport_handshake_frame(tag: &str) -> Result<Vec<u8>, io::Error> {
    let bytes = tag.as_bytes();
    if bytes.is_empty() || bytes.len() > GATEWAY_TRANSPORT_MAX_TAG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway transport authentication tag is invalid",
        ));
    }
    let length = u16::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway transport authentication tag is too long",
        )
    })?;
    let mut frame = Vec::with_capacity(GATEWAY_TRANSPORT_HANDSHAKE_MAGIC.len() + 2 + bytes.len());
    frame.extend_from_slice(GATEWAY_TRANSPORT_HANDSHAKE_MAGIC);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}

pub(crate) fn gateway_transport_handshake_frame_for_client(
    tag: &str,
) -> Result<Vec<u8>, io::Error> {
    gateway_transport_handshake_frame(tag)
}

impl GatewaySessionRuntime {
    #[cfg(unix)]
    pub(crate) fn start(
        gateway: Arc<GatewayService>,
        _overlay_root: &Path,
        credentials: Arc<dyn GatewayCredentialResolver>,
        hook_authorizations: Arc<dyn GatewayHookAuthorizationSource>,
        authority_key: SessionAuthorityKey,
        session_id: String,
        process: ProcessEvidence,
    ) -> Result<Self, GatewaySessionError> {
        let socket_directory = create_socket_directory()?;
        let socket_path = socket_directory.join("mcp.sock");
        let listener = StdUnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        let authentication_tag = gateway_transport_authentication_tag(
            &authority_key,
            &session_id,
            &process,
            &socket_path,
        )
        .map_err(|_| GatewaySessionError::Authentication)?;

        let server = GatewayMcpServer::new(
            Arc::clone(&gateway),
            credentials,
            GatewayRuntimeTimeouts::default(),
        )
        .with_hook_authorization_source(hook_authorizations);
        let notifier = GatewayPrimaryNotifier::default();
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let listener_gateway = Arc::clone(&gateway);
        let thread = thread::Builder::new()
            .name("unpin-session-gateway".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(run_listener(
                    listener,
                    listener_gateway,
                    server,
                    notifier,
                    authentication_tag,
                    receiver,
                ))
            })?;
        Ok(Self {
            gateway,
            socket_directory,
            socket_path,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn start(
        _gateway: Arc<GatewayService>,
        _overlay_root: &Path,
        _credentials: Arc<dyn unpin_cli::mcp_runtime::GatewayCredentialResolver>,
        _hook_authorizations: Arc<dyn unpin_cli::mcp_runtime::GatewayHookAuthorizationSource>,
        _authority_key: unpin_core::sessions::SessionAuthorityKey,
        _session_id: String,
        _process: unpin_core::sessions::ProcessEvidence,
    ) -> Result<Self, GatewaySessionError> {
        Err(GatewaySessionError::PlatformUnsupported)
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn shutdown(mut self) -> Result<(), GatewaySessionError> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), GatewaySessionError> {
        let runtime_was_active = self.shutdown.is_some() || self.thread.is_some();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let listener_result = self.thread.take().map_or(Ok(()), |thread| {
            thread
                .join()
                .map_err(|_| GatewaySessionError::RuntimePanicked)?
        });
        let reconciliation = if runtime_was_active {
            self.gateway
                .control_plane()
                .reconcile_stopped_runtime(crate::unix_now())
                .map(|_| ())
                .map_err(GatewaySessionError::Gateway)
        } else {
            Ok(())
        };
        let result = match (listener_result, reconciliation) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        };
        match fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if result.is_ok() => return Err(error.into()),
            Err(_) => {}
        }
        match fs::remove_dir(&self.socket_directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if result.is_ok() => return Err(error.into()),
            Err(_) => {}
        }
        result
    }
}

#[cfg(unix)]
fn create_socket_directory() -> Result<PathBuf, GatewaySessionError> {
    use std::os::unix::fs::DirBuilderExt;

    for _ in 0..8 {
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let nonce = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = PathBuf::from("/tmp").join(format!("unpin-gw-{}-{nonce}", std::process::id()));
        let mut builder = fs::DirBuilder::new();
        match builder.mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(GatewaySessionError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique session gateway socket directory",
    )))
}

impl Drop for GatewaySessionRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(unix)]
async fn authenticate_gateway_connection(
    mut stream: tokio::net::UnixStream,
    expected_tag: &str,
) -> Result<tokio::net::UnixStream, io::Error> {
    use tokio::io::AsyncReadExt;

    let mut magic = vec![0_u8; GATEWAY_TRANSPORT_HANDSHAKE_MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    if magic != GATEWAY_TRANSPORT_HANDSHAKE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway transport handshake rejected",
        ));
    }
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > GATEWAY_TRANSPORT_MAX_TAG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway transport handshake rejected",
        ));
    }
    let mut received = vec![0_u8; length];
    stream.read_exact(&mut received).await?;
    if !constant_time_equal(received.as_slice(), expected_tag.as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gateway transport handshake rejected",
        ));
    }
    Ok(stream)
}

#[cfg(unix)]
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (&left, &right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(unix)]
async fn run_listener(
    listener: StdUnixListener,
    gateway: Arc<GatewayService>,
    server: GatewayMcpServer,
    notifier: GatewayPrimaryNotifier,
    authentication_tag: String,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), GatewaySessionError> {
    const MAX_CONCURRENT_CONNECTIONS: usize = 32;

    let listener = tokio::net::UnixListener::from_std(listener)?;
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(completed) = completed {
                    // A transport or protocol failure belongs to that connection.
                    // Keep accepting later control connections for the live session;
                    // only a panicked task is a listener-runtime failure.
                    let _connection_result =
                        completed.map_err(|_| GatewaySessionError::RuntimePanicked)?;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let connection_gateway = Arc::clone(&gateway);
                let connection_notifier = notifier.clone();
                let connection_server = server.clone();
                let connection_authentication_tag = authentication_tag.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let stream = match tokio::time::timeout(
                        GATEWAY_TRANSPORT_HANDSHAKE_TIMEOUT,
                        authenticate_gateway_connection(stream, &connection_authentication_tag),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(_)) | Err(_) => return Ok(()),
                    };
                    // Authentication must complete before this call. In particular, do not
                    // move accept_connection above the handshake: it may install Primary.
                    let claim = match connection_gateway.accept_connection() {
                        Ok(claim) => claim,
                        Err(_) => return Ok(()),
                    };
                    let (read, write) = stream.into_split();
                    let server = connection_server
                        .with_connection_claim(claim.clone())
                        .with_primary_notifier(connection_notifier.clone());
                    let result = serve_gateway_io(server, read, write).await;
                    // Fence this transport claim without reconciling the
                    // durable lease: the launched child may still be alive
                    // after its MCP proxy closes. GatewaySessionRuntime::stop
                    // performs the durable runtime reconciliation once the
                    // child lifecycle has actually ended.
                    let _ = connection_gateway.connection_registry().disconnect(&claim);
                    if claim.is_primary() {
                        connection_notifier.clear(&claim);
                    }
                    result
                });
            }
        }
    }
    connections.abort_all();
    while let Some(completed) = connections.join_next().await {
        if let Err(error) = completed
            && !error.is_cancelled()
        {
            return Err(GatewaySessionError::RuntimePanicked);
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_gateway_proxy(socket_path: &Path) -> Result<(), GatewaySessionError> {
    if !socket_path.is_absolute() {
        return Err(GatewaySessionError::InvalidSocket);
    }
    let metadata =
        fs::symlink_metadata(socket_path).map_err(|_| GatewaySessionError::InvalidSocket)?;
    use std::os::unix::fs::FileTypeExt;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(GatewaySessionError::InvalidSocket);
    }
    let authentication_tag = std::env::var(GATEWAY_TRANSPORT_AUTHENTICATION_TAG_ENV)
        .map_err(|_| GatewaySessionError::AuthenticationUnavailable)?;
    let mut stream = StdUnixStream::connect(socket_path)?;
    let frame = gateway_transport_handshake_frame(&authentication_tag)?;
    use std::io::Write as _;
    stream.write_all(&frame)?;
    let mut input_stream = stream.try_clone()?;
    let mut output_stream = stream;
    let input = thread::spawn(move || -> io::Result<()> {
        let mut stdin = io::stdin().lock();
        io::copy(&mut stdin, &mut input_stream)?;
        input_stream.shutdown(std::net::Shutdown::Write)
    });
    let output = thread::spawn(move || -> io::Result<()> {
        let mut stdout = io::stdout().lock();
        io::copy(&mut output_stream, &mut stdout)?;
        use io::Write;
        stdout.flush()
    });
    input
        .join()
        .map_err(|_| GatewaySessionError::ProxyPanicked)??;
    output
        .join()
        .map_err(|_| GatewaySessionError::ProxyPanicked)??;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn run_gateway_proxy(_socket_path: &Path) -> Result<(), GatewaySessionError> {
    Err(GatewaySessionError::PlatformUnsupported)
}

#[derive(Debug)]
pub(crate) enum GatewaySessionError {
    Io(io::Error),
    Gateway(GatewayError),
    Runtime(GatewayRuntimeError),
    Authentication,
    #[cfg(unix)]
    AuthenticationUnavailable,
    #[cfg(unix)]
    InvalidSocket,
    RuntimePanicked,
    #[cfg(unix)]
    ProxyPanicked,
    #[cfg(not(unix))]
    PlatformUnsupported,
}

impl From<io::Error> for GatewaySessionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<GatewayRuntimeError> for GatewaySessionError {
    fn from(error: GatewayRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl std::fmt::Display for GatewaySessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session gateway I/O failed: {error}"),
            Self::Gateway(error) => write!(formatter, "session gateway cleanup failed: {error}"),
            Self::Runtime(error) => write!(formatter, "session gateway failed: {error}"),
            Self::Authentication => {
                formatter.write_str("session gateway transport authentication failed")
            }
            #[cfg(unix)]
            Self::AuthenticationUnavailable => {
                formatter.write_str("session gateway proxy authentication is unavailable")
            }
            #[cfg(unix)]
            Self::InvalidSocket => formatter.write_str("session gateway socket is invalid"),
            Self::RuntimePanicked => formatter.write_str("session gateway runtime panicked"),
            #[cfg(unix)]
            Self::ProxyPanicked => formatter.write_str("session gateway proxy panicked"),
            #[cfg(not(unix))]
            Self::PlatformUnsupported => {
                formatter.write_str("session gateway sockets are unsupported on this platform")
            }
        }
    }
}

impl std::error::Error for GatewaySessionError {}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        collections::BTreeSet, io::Write, net::Shutdown, os::unix::net::UnixStream, sync::Arc,
        time::Duration,
    };

    use rmcp::ServiceExt;
    use unpin_cli::mcp_runtime::{NoGatewayCredentials, NoGatewayHookAuthorizations};
    use unpin_core::{
        catalog::Catalog,
        gateway::{GatewayControlPlane, GatewayExposure, GatewayLimits, GatewayService},
        providers::ProviderId,
        sessions::{
            BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
            PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
        },
    };

    use super::{
        GatewaySessionRuntime, gateway_transport_authentication_tag,
        gateway_transport_handshake_frame_for_client,
    };

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn gateway(root: &std::path::Path) -> Arc<GatewayService> {
        gateway_with_in_flight(root, false)
    }

    fn start_runtime(
        gateway: Arc<GatewayService>,
        root: &std::path::Path,
    ) -> (GatewaySessionRuntime, String) {
        let authority_key = SessionAuthorityKey::new([0x53; 32]);
        let session_id = "gateway-session-test".to_string();
        let process = ProcessEvidence {
            pid: std::process::id(),
            start_marker: "gateway-session-test-process".to_string(),
        };
        let runtime = GatewaySessionRuntime::start(
            gateway,
            root,
            Arc::new(NoGatewayCredentials),
            Arc::new(NoGatewayHookAuthorizations),
            authority_key.clone(),
            session_id.clone(),
            process.clone(),
        )
        .unwrap();
        let tag = gateway_transport_authentication_tag(
            &authority_key,
            &session_id,
            &process,
            runtime.socket_path(),
        )
        .unwrap();
        (runtime, tag)
    }

    async fn authenticate_client(
        socket_path: &std::path::Path,
        authentication_tag: &str,
    ) -> tokio::net::UnixStream {
        use tokio::io::AsyncWriteExt;

        let mut stream = tokio::net::UnixStream::connect(socket_path).await.unwrap();
        let frame = gateway_transport_handshake_frame_for_client(authentication_tag).unwrap();
        stream.write_all(&frame).await.unwrap();
        stream
    }

    fn gateway_with_in_flight(
        root: &std::path::Path,
        retain_in_flight_call: bool,
    ) -> Arc<GatewayService> {
        let pinned = PinnedExposure {
            revision: digest('e'),
            profile: PinnedProfile::None,
            capability_locks: None,
        };
        let limits = GatewayLimits::default();
        let exposure = GatewayExposure::compile(
            pinned.clone(),
            ProviderId::Codex,
            &Catalog::default(),
            None,
            Vec::new(),
            limits,
        )
        .expect("empty gateway exposure");
        let manager =
            SessionManager::with_authority_key(root, SessionAuthorityKey::new([0x53; 32]));
        let now = crate::unix_now();
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            workspace_revision: None,
            exposure: pinned,
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "gateway-session-concurrency".to_string(),
            },
            connection_scope_id: "gateway-session-concurrency".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: now + 600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "gateway-session-owner".to_string(),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let authority = manager.prepare_bootstrap(request, now).unwrap();
        let session = manager.claim_bootstrap(&authority, &claim, now).unwrap();
        if retain_in_flight_call {
            manager
                .admit_call(&session.handle, &session.lease.revision, now + 1)
                .expect("retain in-flight admission");
        }
        let control =
            GatewayControlPlane::new(manager, session.handle, limits.maximum_concurrent_calls)
                .unwrap();
        Arc::new(GatewayService::new(control, exposure, limits).unwrap())
    }

    #[test]
    fn open_client_does_not_block_second_gateway_connection() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let gateway = gateway(&root);
        let (runtime, authentication_tag) = start_runtime(Arc::clone(&gateway), &root);
        let _held_open = UnixStream::connect(runtime.socket_path()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let socket_path = runtime.socket_path().to_path_buf();
        let client_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let names = client_runtime.block_on(async move {
            let stream = authenticate_client(&socket_path, &authentication_tag).await;
            let mut client = tokio::time::timeout(Duration::from_secs(2), ().serve(stream))
                .await
                .expect("second client initialize timeout")
                .expect("second client initialize");
            let tools = tokio::time::timeout(Duration::from_secs(2), client.list_all_tools())
                .await
                .expect("second client tools timeout")
                .expect("second client tools");
            let names = tools
                .into_iter()
                .map(|tool| tool.name.into_owned())
                .collect::<BTreeSet<_>>();
            client
                .close_with_timeout(Duration::from_secs(2))
                .await
                .expect("close second client");
            names
        });

        for name in [
            "unpin_workflow_cancel_transition",
            "unpin_workflow_enter_mode",
            "unpin_workflow_modes",
            "unpin_workflow_status",
        ] {
            assert!(names.contains(name), "authenticated client lacks {name}");
        }
        runtime.shutdown().unwrap();
    }

    #[test]
    fn disconnected_client_does_not_stop_gateway_listener() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let service = gateway(&root);
        let (runtime, authentication_tag) = start_runtime(Arc::clone(&service), &root);
        let socket_path = runtime.socket_path().to_path_buf();
        let client_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let mut disconnected = UnixStream::connect(&socket_path).unwrap();
        let _ = disconnected.write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"disconnect-fixture","version":"1"}}}
"#,
            );
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            service.primary_connection_claim().unwrap().is_none(),
            "unauthenticated clients must not install a Primary claim"
        );
        let _ = disconnected.shutdown(Shutdown::Both);
        drop(disconnected);
        let mut racing = UnixStream::connect(&socket_path).unwrap();
        let forged_frame = gateway_transport_handshake_frame_for_client(&"0".repeat(64)).unwrap();
        let _ = racing.write_all(&forged_frame);
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            service.primary_connection_claim().unwrap().is_none(),
            "a forged transport capability must not install a Primary claim"
        );
        let _ = racing.shutdown(Shutdown::Both);
        drop(racing);
        let disconnect_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while service.primary_connection_claim().unwrap().is_some() {
            assert!(
                std::time::Instant::now() < disconnect_deadline,
                "gateway did not reap disconnected client"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let names = client_runtime.block_on(async {
            let stream = authenticate_client(&socket_path, &authentication_tag).await;
            let mut client = tokio::time::timeout(Duration::from_secs(2), ().serve(stream))
                .await
                .expect("second client initialize timeout")
                .expect("second client initialize");
            let tools = tokio::time::timeout(Duration::from_secs(2), client.list_all_tools())
                .await
                .expect("second client tools timeout")
                .expect("second client tools");
            let names = tools
                .into_iter()
                .map(|tool| tool.name.into_owned())
                .collect::<BTreeSet<_>>();
            client
                .close_with_timeout(Duration::from_secs(2))
                .await
                .expect("close second client");
            names
        });

        assert!(names.contains("unpin_workflow_cancel_transition"));
        assert!(names.contains("unpin_workflow_enter_mode"));
        assert!(names.contains("unpin_workflow_modes"));
        assert!(names.contains("unpin_workflow_status"));
        runtime.shutdown().unwrap();
    }

    #[test]
    fn shutdown_fences_and_reconciles_residual_admissions() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let gateway = gateway_with_in_flight(&root, true);
        assert_eq!(
            gateway
                .control_plane()
                .status()
                .expect("status before shutdown")
                .in_flight_calls,
            1
        );
        let (runtime, _) = start_runtime(Arc::clone(&gateway), &root);

        runtime.shutdown().unwrap();

        let status = gateway
            .control_plane()
            .status()
            .expect("status after shutdown");
        assert_eq!(status.in_flight_calls, 0);
        assert!(!status.admission_open);
    }
}
