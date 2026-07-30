use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, hash_map::RandomState},
    hash::BuildHasher,
    io,
    marker::PhantomData,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use rmcp::{
    ErrorData as McpError, RoleClient, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorCode,
        Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
        ServerInfo, Tool, ToolAnnotations,
    },
    service::{
        RequestContext, RoleServer, RunningService, RxJsonRpcMessage, ServiceRole, TxJsonRpcMessage,
    },
    transport::{
        StreamableHttpClientTransport, Transport,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, RwLock},
};
use unpin_core::gateway::{
    GatewayCallPermit, GatewayError, GatewayHookCallContext, GatewayService,
    PreparedStdioExecution, ProjectedTool, UpstreamIdentity, UpstreamTransportKind,
};
use unpin_core::hooks::{
    HookAction, HookActionOutcome, HookAfterResult, HookBeforeDecision, HookBeforeResult,
    HookDispatchPlan, HookDispatchStep, HookEventFamily, HookFailurePolicy, HookInvocationChain,
    HookRewriteAuthorization, HookRewriteRequest,
};
use zeroize::Zeroize;

mod bounded_http;

use bounded_http::BoundedHttpClient;

const SEARCH_SKILLS_TOOL: &str = "unpin_search_skills";
const LOAD_SKILL_TOOL: &str = "unpin_load_skill";
const SESSION_STATUS_TOOL: &str = "unpin_get_session_status";
const DEFAULT_SEARCH_LIMIT: usize = 10;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_UPSTREAM_STDIO_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const MCP_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_MALFORMED_STDIO_FRAMES: u8 = 3;
const HTTP_POOL_MAX_IDLE_PER_HOST: usize = 1;
const HTTP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

fn build_hardened_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(HTTP_POOL_MAX_IDLE_PER_HOST)
        .pool_idle_timeout(HTTP_POOL_IDLE_TIMEOUT)
        .build()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRuntimeTimeouts {
    pub connect: Duration,
    pub call: Duration,
}

impl Default for GatewayRuntimeTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(15),
            call: Duration::from_secs(60),
        }
    }
}

pub struct BoundBearerToken {
    key_id: String,
    identity_digest: String,
    token: Vec<u8>,
}

impl BoundBearerToken {
    /// Creates resolver-owned secret material bound to one exact upstream.
    ///
    /// Resolver-owned bytes are cleared on drop. HTTP transports require their
    /// own plaintext header copy, so process memory and core dumps remain part
    /// of credential threat model for lifetime of that connection.
    pub fn new(
        key_id: impl Into<String>,
        identity: &UpstreamIdentity,
        token: impl Into<String>,
    ) -> Result<Self, GatewayRuntimeError> {
        identity
            .verify()
            .map_err(|_| GatewayRuntimeError::InvalidUpstreamIdentity)?;
        let key_id = key_id.into();
        let token = token.into();
        if key_id.trim().is_empty()
            || key_id.len() > 256
            || key_id.chars().any(char::is_control)
            || token.is_empty()
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || token.chars().any(char::is_control)
        {
            return Err(GatewayRuntimeError::CredentialUnavailable);
        }
        Ok(Self {
            key_id,
            identity_digest: identity.digest.clone(),
            token: token.into_bytes(),
        })
    }

    fn verify(&self, key_id: &str, identity: &UpstreamIdentity) -> Result<(), GatewayRuntimeError> {
        if self.key_id == key_id && self.identity_digest == identity.digest {
            Ok(())
        } else {
            Err(GatewayRuntimeError::CredentialUnavailable)
        }
    }

    fn connection_fingerprint(&self, state: &RandomState) -> String {
        format!("{:016x}", state.hash_one(&self.token))
    }
}

impl std::fmt::Debug for BoundBearerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundBearerToken")
            .field("key_id", &self.key_id)
            .field("identity_digest", &self.identity_digest)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl Drop for BoundBearerToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

pub trait GatewayCredentialResolver: Send + Sync {
    fn resolve(
        &self,
        key_id: &str,
        identity: &UpstreamIdentity,
    ) -> Result<BoundBearerToken, GatewayRuntimeError>;
}

pub trait GatewayHookAuthorizationSource: Send + Sync {
    fn authorizations_for(
        &self,
        plan: &HookDispatchPlan,
    ) -> Result<Vec<HookRewriteAuthorization>, GatewayError>;
}

#[derive(Debug, Default)]
pub struct NoGatewayHookAuthorizations;

impl GatewayHookAuthorizationSource for NoGatewayHookAuthorizations {
    fn authorizations_for(
        &self,
        _plan: &HookDispatchPlan,
    ) -> Result<Vec<HookRewriteAuthorization>, GatewayError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
pub struct NoGatewayCredentials;

impl GatewayCredentialResolver for NoGatewayCredentials {
    fn resolve(
        &self,
        _key_id: &str,
        _identity: &UpstreamIdentity,
    ) -> Result<BoundBearerToken, GatewayRuntimeError> {
        Err(GatewayRuntimeError::CredentialUnavailable)
    }
}

struct UpstreamClient {
    identity: UpstreamIdentity,
    credential_key_id: Option<String>,
    credential_fingerprint: Option<String>,
    service: RunningService<RoleClient, ()>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UpstreamConnectionKey {
    identity_digest: String,
    credential_key_id: Option<String>,
    credential_fingerprint: Option<String>,
    maximum_message_bytes: usize,
}

impl UpstreamConnectionKey {
    fn same_credential_slot(&self, other: &Self) -> bool {
        self.identity_digest == other.identity_digest
            && self.credential_key_id == other.credential_key_id
    }
}

fn evict_replaced_connection<V>(
    clients: &mut BTreeMap<UpstreamConnectionKey, V>,
    replacement: &UpstreamConnectionKey,
) {
    clients.retain(|key, _| !key.same_credential_slot(replacement));
}

struct UpstreamCallRequest<'a> {
    identity: &'a UpstreamIdentity,
    credential_key_id: Option<&'a str>,
    authorization: Option<BoundBearerToken>,
    tool_name: &'a str,
    arguments: JsonObject,
    timeouts: GatewayRuntimeTimeouts,
    maximum_message_bytes: usize,
}

struct UpstreamConnectRequest<'a> {
    connection_key: &'a UpstreamConnectionKey,
    identity: &'a UpstreamIdentity,
    credential_key_id: Option<&'a str>,
    credential_fingerprint: Option<&'a str>,
    authorization: Option<BoundBearerToken>,
    connect_timeout: Duration,
    maximum_message_bytes: usize,
}

#[derive(Default)]
pub struct McpUpstreamPool {
    clients: Mutex<BTreeMap<UpstreamConnectionKey, Arc<UpstreamClient>>>,
    fingerprint_state: RandomState,
}

impl std::fmt::Debug for McpUpstreamPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpUpstreamPool")
            .finish_non_exhaustive()
    }
}

impl McpUpstreamPool {
    pub async fn call(
        &self,
        identity: &UpstreamIdentity,
        credential_key_id: Option<&str>,
        authorization: Option<BoundBearerToken>,
        tool_name: &str,
        arguments: JsonObject,
        timeouts: GatewayRuntimeTimeouts,
    ) -> Result<CallToolResult, GatewayRuntimeError> {
        self.call_with_message_limit(UpstreamCallRequest {
            identity,
            credential_key_id,
            authorization,
            tool_name,
            arguments,
            timeouts,
            maximum_message_bytes: MAX_UPSTREAM_STDIO_MESSAGE_BYTES,
        })
        .await
    }

    async fn call_with_message_limit(
        &self,
        request: UpstreamCallRequest<'_>,
    ) -> Result<CallToolResult, GatewayRuntimeError> {
        validate_authorization(
            request.identity,
            request.credential_key_id,
            request.authorization.as_ref(),
        )?;
        let timeouts = request.timeouts;
        let maximum_message_bytes = request.maximum_message_bytes;
        if timeouts.connect.is_zero() || timeouts.call.is_zero() || maximum_message_bytes == 0 {
            return Err(GatewayRuntimeError::InvalidTimeout);
        }
        let credential_fingerprint = request
            .authorization
            .as_ref()
            .map(|authorization| authorization.connection_fingerprint(&self.fingerprint_state));
        let connection_key = UpstreamConnectionKey {
            identity_digest: request.identity.digest.clone(),
            credential_key_id: request.credential_key_id.map(str::to_string),
            credential_fingerprint: credential_fingerprint.clone(),
            maximum_message_bytes,
        };
        let client = self
            .client(UpstreamConnectRequest {
                connection_key: &connection_key,
                identity: request.identity,
                credential_key_id: request.credential_key_id,
                credential_fingerprint: credential_fingerprint.as_deref(),
                authorization: request.authorization,
                connect_timeout: timeouts.connect,
                maximum_message_bytes,
            })
            .await?;
        if client.identity != *request.identity
            || client.credential_key_id.as_deref() != request.credential_key_id
            || client.credential_fingerprint.as_deref() != credential_fingerprint.as_deref()
        {
            return Err(GatewayRuntimeError::InvalidUpstreamIdentity);
        }
        let tool_request = CallToolRequestParams::new(request.tool_name.to_string())
            .with_arguments(request.arguments);
        match tokio::time::timeout(timeouts.call, client.service.call_tool(tool_request)).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                self.clients.lock().await.remove(&connection_key);
                Err(GatewayRuntimeError::UpstreamCallFailed)
            }
            Err(_) => {
                self.clients.lock().await.remove(&connection_key);
                Err(GatewayRuntimeError::UpstreamCallTimedOut)
            }
        }
    }

    async fn client(
        &self,
        request: UpstreamConnectRequest<'_>,
    ) -> Result<Arc<UpstreamClient>, GatewayRuntimeError> {
        {
            let mut clients = self.clients.lock().await;
            if let Some(client) = clients.get(request.connection_key)
                && !client.service.is_closed()
            {
                return Ok(Arc::clone(client));
            }
            clients.remove(request.connection_key);
        }
        let service = connect_upstream(
            request.identity,
            request.authorization,
            request.connect_timeout,
            request.maximum_message_bytes,
        )
        .await?;
        let candidate = Arc::new(UpstreamClient {
            identity: request.identity.clone(),
            credential_key_id: request.credential_key_id.map(str::to_string),
            credential_fingerprint: request.credential_fingerprint.map(str::to_string),
            service,
        });
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(request.connection_key)
            && !client.service.is_closed()
        {
            return Ok(Arc::clone(client));
        }
        evict_replaced_connection(&mut clients, request.connection_key);
        clients.insert(request.connection_key.clone(), Arc::clone(&candidate));
        Ok(candidate)
    }
}

async fn connect_upstream(
    identity: &UpstreamIdentity,
    authorization: Option<BoundBearerToken>,
    connect_timeout: Duration,
    maximum_message_bytes: usize,
) -> Result<RunningService<RoleClient, ()>, GatewayRuntimeError> {
    match identity.transport {
        UpstreamTransportKind::Stdio => {
            if authorization.is_some() {
                return Err(GatewayRuntimeError::CredentialUnavailable);
            }
            let identity = identity.clone();
            let prepared = tokio::task::spawn_blocking(move || identity.prepare_stdio_execution())
                .await
                .map_err(|_| GatewayRuntimeError::InvalidUpstreamIdentity)?
                .map_err(|_| GatewayRuntimeError::InvalidUpstreamIdentity)?;
            let mut command = tokio::process::Command::new(prepared.program());
            command
                .env_clear()
                .envs(prepared.environment())
                .args(prepared.arguments())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            configure_verified_stdio_descriptors(&mut command, &prepared)?;
            let mut child = command
                .spawn()
                .map_err(|_| GatewayRuntimeError::UpstreamConnectFailed)?;
            let stdout = child
                .stdout
                .take()
                .ok_or(GatewayRuntimeError::UpstreamConnectFailed)?;
            let stdin = child
                .stdin
                .take()
                .ok_or(GatewayRuntimeError::UpstreamConnectFailed)?;
            let transport =
                BoundedChildTransport::new(child, stdout, stdin, prepared, maximum_message_bytes);
            tokio::time::timeout(connect_timeout, ().serve(transport))
                .await
                .map_err(|_| GatewayRuntimeError::UpstreamConnectTimedOut)?
                .map_err(|_| GatewayRuntimeError::UpstreamConnectFailed)
        }
        UpstreamTransportKind::StreamableHttp => {
            let identity_to_verify = identity.clone();
            tokio::task::spawn_blocking(move || identity_to_verify.verify())
                .await
                .map_err(|_| GatewayRuntimeError::InvalidUpstreamIdentity)?
                .map_err(|_| GatewayRuntimeError::InvalidUpstreamIdentity)?;
            let mut config =
                StreamableHttpClientTransportConfig::with_uri(identity.endpoint.clone())
                    .reinit_on_expired_session(false)
                    .max_sse_event_size(maximum_message_bytes);
            if let Some(mut authorization) = authorization {
                // rmcp requires an owned String and retains a transport-owned plaintext
                // header copy. BoundBearerToken only zeroes resolver-owned bytes; callers
                // must treat process memory and core dumps as secret-bearing. Config expects
                // raw bearer token; bounded HTTP client adds exactly one `Bearer` scheme.
                let token = String::from_utf8(std::mem::take(&mut authorization.token))
                    .map_err(|_| GatewayRuntimeError::CredentialUnavailable)?;
                config = config.auth_header(token);
            }
            let client = BoundedHttpClient::new(maximum_message_bytes)
                .map_err(|_| GatewayRuntimeError::UpstreamConnectFailed)?;
            let transport = StreamableHttpClientTransport::with_client(client, config);
            tokio::time::timeout(connect_timeout, ().serve(transport))
                .await
                .map_err(|_| GatewayRuntimeError::UpstreamConnectTimedOut)?
                .map_err(|_| GatewayRuntimeError::UpstreamConnectFailed)
        }
    }
}

#[cfg(unix)]
fn configure_verified_stdio_descriptors(
    command: &mut tokio::process::Command,
    prepared: &PreparedStdioExecution,
) -> Result<(), GatewayRuntimeError> {
    use std::os::unix::process::CommandExt;

    let descriptors = prepared.inherited_file_descriptors();
    // Descriptor flags are copied at fork. Clearing CLOEXEC in pre_exec affects
    // only this child, leaves parent descriptors protected from unrelated
    // children, and keeps descriptor-backed script paths readable by interpreter.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            for descriptor in &descriptors {
                if system_fcntl(*descriptor, F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_verified_stdio_descriptors(
    _command: &mut tokio::process::Command,
    _prepared: &PreparedStdioExecution,
) -> Result<(), GatewayRuntimeError> {
    Err(GatewayRuntimeError::InvalidUpstreamIdentity)
}

#[cfg(unix)]
const F_SETFD: std::ffi::c_int = 2;

#[cfg(unix)]
unsafe extern "C" {
    fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
}

#[cfg(unix)]
unsafe fn system_fcntl(
    fd: std::ffi::c_int,
    command: std::ffi::c_int,
    flags: std::ffi::c_int,
) -> std::ffi::c_int {
    // SAFETY: fcntl receives valid inherited descriptor, F_SETFD, integer flags.
    unsafe { fcntl(fd, command, flags) }
}

struct BoundedLineTransport<Role, R, W>
where
    Role: ServiceRole,
    R: AsyncRead,
    W: AsyncWrite,
{
    read: BufReader<R>,
    line: Vec<u8>,
    write: Arc<Mutex<Option<W>>>,
    maximum_message_bytes: usize,
    malformed_frames: u8,
    role: PhantomData<fn() -> Role>,
}

impl<Role, R, W> BoundedLineTransport<Role, R, W>
where
    Role: ServiceRole,
    R: AsyncRead,
    W: AsyncWrite,
{
    fn new(read: R, write: W, maximum_message_bytes: usize) -> Self {
        Self {
            read: BufReader::new(read),
            line: Vec::new(),
            write: Arc::new(Mutex::new(Some(write))),
            maximum_message_bytes,
            malformed_frames: 0,
            role: PhantomData,
        }
    }
}

impl<Role, R, W> Transport<Role> for BoundedLineTransport<Role, R, W>
where
    Role: ServiceRole,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<Role>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let write = Arc::clone(&self.write);
        let maximum_message_bytes = self.maximum_message_bytes;
        async move {
            let message = serde_json::to_vec(&item).map_err(io::Error::other)?;
            if message.len() > maximum_message_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP message exceeds configured limit",
                ));
            }
            let mut write = write.lock().await;
            let write = write
                .as_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "transport closed"))?;
            write.write_all(&message).await?;
            write.write_all(b"\n").await?;
            write.flush().await
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<Role>> {
        loop {
            let available = self.read.fill_buf().await.ok()?;
            if available.is_empty() {
                self.line.clear();
                return None;
            }
            let delimiter = available.iter().position(|byte| *byte == b'\n');
            let consumed = delimiter.map_or(available.len(), |position| position + 1);
            if self.line.len().saturating_add(consumed) > self.maximum_message_bytes + 1 {
                self.line.clear();
                tracing::warn!("closing MCP stdio transport after oversized frame");
                return None;
            }
            self.line.extend_from_slice(&available[..consumed]);
            self.read.consume(consumed);
            if delimiter.is_none() {
                continue;
            }
            if self.line.last() == Some(&b'\n') {
                self.line.pop();
            }
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            if self.line.is_empty() {
                continue;
            }
            let parsed = serde_json::from_slice(&self.line).ok();
            self.line.clear();
            if parsed.is_some() {
                self.malformed_frames = 0;
                return parsed;
            }
            self.malformed_frames = self.malformed_frames.saturating_add(1);
            tracing::warn!(
                malformed_frames = self.malformed_frames,
                "discarding malformed MCP stdio frame"
            );
            if self.malformed_frames >= MAX_MALFORMED_STDIO_FRAMES {
                return None;
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        let mut write = self.write.lock().await;
        if let Some(mut write) = write.take() {
            write.shutdown().await?;
        }
        Ok(())
    }
}

struct BoundedChildTransport {
    child: tokio::process::Child,
    _execution: PreparedStdioExecution,
    transport:
        BoundedLineTransport<RoleClient, tokio::process::ChildStdout, tokio::process::ChildStdin>,
}

impl BoundedChildTransport {
    fn new(
        child: tokio::process::Child,
        stdout: tokio::process::ChildStdout,
        stdin: tokio::process::ChildStdin,
        execution: PreparedStdioExecution,
        maximum_message_bytes: usize,
    ) -> Self {
        Self {
            child,
            _execution: execution,
            transport: BoundedLineTransport::new(stdout, stdin, maximum_message_bytes),
        }
    }
}

impl Transport<RoleClient> for BoundedChildTransport {
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.transport.send(item)
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleClient>>> + Send {
        self.transport.receive()
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.transport.close().await?;
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        let _status = self.child.wait().await?;
        Ok(())
    }
}

fn validate_authorization(
    identity: &UpstreamIdentity,
    credential_key_id: Option<&str>,
    authorization: Option<&BoundBearerToken>,
) -> Result<(), GatewayRuntimeError> {
    match (credential_key_id, authorization) {
        (Some(key_id), Some(authorization)) => authorization.verify(key_id, identity),
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(GatewayRuntimeError::CredentialUnavailable),
    }
}

#[derive(Clone)]
pub struct GatewayMcpServer {
    gateway: Arc<GatewayService>,
    upstreams: Arc<McpUpstreamPool>,
    credentials: Arc<dyn GatewayCredentialResolver>,
    hook_authorizations: Arc<dyn GatewayHookAuthorizationSource>,
    hook_http_client: Option<reqwest::Client>,
    timeouts: GatewayRuntimeTimeouts,
    list_change_gate: Arc<RwLock<()>>,
}

impl std::fmt::Debug for GatewayMcpServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayMcpServer")
            .field("gateway", &self.gateway)
            .field("upstreams", &self.upstreams)
            .field("credentials", &"[REDACTED]")
            .field("hook_authorizations", &"[REDACTED]")
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl GatewayMcpServer {
    #[must_use]
    pub fn new(
        gateway: Arc<GatewayService>,
        credentials: Arc<dyn GatewayCredentialResolver>,
        timeouts: GatewayRuntimeTimeouts,
    ) -> Self {
        Self {
            gateway,
            upstreams: Arc::new(McpUpstreamPool::default()),
            credentials,
            hook_authorizations: Arc::new(NoGatewayHookAuthorizations),
            hook_http_client: build_hardened_http_client().ok(),
            timeouts,
            list_change_gate: Arc::new(RwLock::new(())),
        }
    }

    #[must_use]
    pub fn with_upstream_pool(mut self, upstreams: Arc<McpUpstreamPool>) -> Self {
        self.upstreams = upstreams;
        self
    }

    #[must_use]
    pub fn with_hook_authorization_source(
        mut self,
        hook_authorizations: Arc<dyn GatewayHookAuthorizationSource>,
    ) -> Self {
        self.hook_authorizations = hook_authorizations;
        self
    }

    async fn call(&self, request: CallToolRequestParams) -> Result<CallToolResult, McpError> {
        let now_unix = unix_now().map_err(|_| internal_error())?;
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        match request.name.as_ref() {
            SEARCH_SKILLS_TOOL => self.search_skills(&arguments, now_unix).await,
            LOAD_SKILL_TOOL => self.load_skill(&arguments, now_unix).await,
            SESSION_STATUS_TOOL => self.session_status(&arguments).await,
            name => self.call_upstream(name, arguments, now_unix).await,
        }
    }

    async fn search_skills(
        &self,
        arguments: &Value,
        now_unix: i64,
    ) -> Result<CallToolResult, McpError> {
        let object = compact_arguments(arguments, &["query", "limit"])?;
        let query = match object.get("query") {
            Some(value) => value
                .as_str()
                .ok_or_else(|| McpError::invalid_params("query must be a string", None))?
                .to_string(),
            None => String::new(),
        };
        let limit = match object.get("limit") {
            Some(value) => {
                let limit = value
                    .as_u64()
                    .filter(|limit| *limit > 0)
                    .ok_or_else(|| McpError::invalid_params("limit must be positive", None))?;
                usize::try_from(limit)
                    .map_err(|_| McpError::invalid_params("limit is too large", None))?
            }
            None => DEFAULT_SEARCH_LIMIT,
        };
        let gateway = Arc::clone(&self.gateway);
        let skills =
            tokio::task::spawn_blocking(move || gateway.search_skills(&query, limit, now_unix))
                .await
                .map_err(|_| internal_error())?
                .map_err(gateway_request_error)?;
        Ok(CallToolResult::structured(json!({ "skills": skills })))
    }

    async fn load_skill(
        &self,
        arguments: &Value,
        now_unix: i64,
    ) -> Result<CallToolResult, McpError> {
        let object = compact_arguments(arguments, &["reference"])?;
        let reference = object
            .get("reference")
            .and_then(Value::as_str)
            .filter(|reference| !reference.is_empty())
            .ok_or_else(|| McpError::invalid_params("reference is required", None))?
            .to_string();
        let gateway = Arc::clone(&self.gateway);
        let loaded = tokio::task::spawn_blocking(move || gateway.load_skill(&reference, now_unix))
            .await
            .map_err(|_| internal_error())?;
        let skill = match loaded {
            Ok(skill) => skill,
            Err(
                GatewayError::CapabilityUnavailable
                | GatewayError::SkillContentChanged
                | GatewayError::SkillContentInvalid,
            ) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "skill is unavailable or changed; refresh session exposure",
                )]));
            }
            Err(error) => return Err(gateway_request_error(error)),
        };
        let value = serde_json::to_value(skill).map_err(|_| internal_error())?;
        Ok(CallToolResult::structured(value))
    }

    async fn session_status(&self, arguments: &Value) -> Result<CallToolResult, McpError> {
        compact_arguments(arguments, &[])?;
        let gateway = Arc::clone(&self.gateway);
        let status = tokio::task::spawn_blocking(move || gateway.control_plane().status())
            .await
            .map_err(|_| internal_error())?
            .map_err(gateway_request_error)?;
        let value = serde_json::to_value(status).map_err(|_| internal_error())?;
        Ok(CallToolResult::structured(value))
    }

    async fn execute_hook_plan(
        &self,
        plan: &HookDispatchPlan,
        rewrite_authorizations: &[HookRewriteAuthorization],
        argument_schema: Option<&Value>,
        hook_call_context: Option<&GatewayHookCallContext>,
    ) -> HookExecutionBatch {
        let maximum_output_bytes = self.gateway.limits().maximum_response_bytes;
        let mut outcomes = BTreeMap::new();
        let mut execution = HookExecutionState {
            arguments: plan.original_arguments().clone(),
            result: plan.original_result().cloned(),
            context_bytes: 0,
        };
        let mut terminal = plan
            .preflight_failures()
            .iter()
            .any(|failure| failure.fail_closed);
        for step in plan.steps() {
            if terminal {
                outcomes.insert(step.handler().id().to_string(), HookActionOutcome::Skipped);
                continue;
            }
            let payload = json!({
                "version": 1,
                "eventFamily": plan.event_family(),
                "toolName": plan.tool_name(),
                "arguments": execution.arguments.clone(),
                "result": execution.result.clone(),
                "ancestry": step.chain().ancestry(),
            });
            let outcome = if let Some((server, tool)) = step.handler().action().mcp_target() {
                match hook_call_context {
                    Some(context) => {
                        self.execute_mcp_hook_action(McpHookActionRequest {
                            hook_call_context: context,
                            server_id: server,
                            tool_name: tool,
                            payload,
                            chain: step.chain().clone(),
                            timeout: Duration::from_millis(step.handler().timeout_ms()),
                            maximum_output_bytes,
                        })
                        .await
                    }
                    None => Err(HookExecutionError::Failed),
                }
            } else {
                execute_hook_action(
                    self.hook_http_client.as_ref(),
                    step.handler().action(),
                    &payload,
                    Duration::from_millis(step.handler().timeout_ms()),
                    maximum_output_bytes,
                )
                .await
            }
            .unwrap_or(HookActionOutcome::Failed);
            terminal = apply_hook_outcome_to_execution(
                plan,
                step,
                &outcome,
                rewrite_authorizations,
                argument_schema,
                &mut execution,
            );
            outcomes.insert(step.handler().id().to_string(), outcome);
        }
        HookExecutionBatch {
            outcomes,
            authorization_ids: hook_authorization_ids(rewrite_authorizations),
            plan_binding: plan.execution_binding(),
        }
    }

    async fn execute_mcp_hook_action(
        &self,
        request: McpHookActionRequest<'_>,
    ) -> Result<HookActionOutcome, HookExecutionError> {
        let now_unix = unix_now().map_err(|_| HookExecutionError::Failed)?;
        let result = tokio::time::timeout(
            request.timeout,
            Box::pin(self.call_hook_upstream(
                request.hook_call_context,
                request.server_id,
                request.tool_name,
                request.payload,
                now_unix,
                request.chain,
            )),
        )
        .await
        .map_err(|_| HookExecutionError::TimedOut)?
        .map_err(|_| HookExecutionError::Failed)?;
        if result.is_error == Some(true) {
            return Err(HookExecutionError::Failed);
        }
        let structured = result
            .structured_content
            .ok_or(HookExecutionError::InvalidOutput)?;
        let encoded =
            serde_json::to_vec(&structured).map_err(|_| HookExecutionError::InvalidOutput)?;
        if encoded.len() > request.maximum_output_bytes {
            return Err(HookExecutionError::OutputLimitExceeded);
        }
        parse_hook_value(&structured)
    }

    async fn finish_failed_call(
        &self,
        guard: &mut PermitGuard,
        error: &GatewayRuntimeError,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        let response = runtime_failure_payload(error);
        let plan = guard.plan_after(false, response.clone()).await?;
        let rewrite_authorizations = self.hook_authorizations_for(&plan).await?;
        let hook_call_context = guard.hook_call_context()?;
        let outcomes = self
            .execute_hook_plan(
                &plan,
                &rewrite_authorizations,
                None,
                Some(&hook_call_context),
            )
            .await;
        guard
            .finish_with_hooks(false, response, outcomes, &rewrite_authorizations, now_unix)
            .await
            .map(|_| ())
    }

    async fn hook_authorizations_for(
        &self,
        plan: &HookDispatchPlan,
    ) -> Result<Vec<HookRewriteAuthorization>, GatewayError> {
        let source = Arc::clone(&self.hook_authorizations);
        let plan = plan.clone();
        tokio::task::spawn_blocking(move || source.authorizations_for(&plan))
            .await
            .map_err(|_| GatewayError::StatePoisoned)?
    }

    async fn call_upstream(
        &self,
        public_name: &str,
        arguments: Value,
        now_unix: i64,
    ) -> Result<CallToolResult, McpError> {
        self.call_upstream_with_chain(
            public_name,
            arguments,
            now_unix,
            HookInvocationChain::default(),
        )
        .await
    }

    async fn call_upstream_with_chain(
        &self,
        public_name: &str,
        arguments: Value,
        now_unix: i64,
        hook_chain: HookInvocationChain,
    ) -> Result<CallToolResult, McpError> {
        let Value::Object(arguments) = arguments else {
            return Err(McpError::invalid_params(
                "arguments must be an object",
                None,
            ));
        };
        let gateway = Arc::clone(&self.gateway);
        let admission_gateway = Arc::clone(&gateway);
        let admission_name = public_name.to_string();
        let admission_arguments = Value::Object(arguments.clone());
        let permit = tokio::task::spawn_blocking(move || {
            admission_gateway.data_plane().admit_tool_with_chain(
                &admission_name,
                &admission_arguments,
                now_unix,
                hook_chain,
            )
        })
        .await
        .map_err(|_| internal_error())?
        .map_err(gateway_request_error)?;
        self.call_admitted_upstream(permit, now_unix).await
    }

    async fn call_hook_upstream(
        &self,
        hook_call_context: &GatewayHookCallContext,
        server_id: &str,
        tool_name: &str,
        arguments: Value,
        now_unix: i64,
        hook_chain: HookInvocationChain,
    ) -> Result<CallToolResult, McpError> {
        let gateway = Arc::clone(&self.gateway);
        let admission_gateway = Arc::clone(&gateway);
        let hook_call_context = hook_call_context.clone();
        let server_id = server_id.to_string();
        let tool_name = tool_name.to_string();
        let permit = tokio::task::spawn_blocking(move || {
            admission_gateway.data_plane().admit_hook_tool(
                &hook_call_context,
                &server_id,
                &tool_name,
                &arguments,
                now_unix,
                hook_chain,
            )
        })
        .await
        .map_err(|_| internal_error())?
        .map_err(gateway_request_error)?;
        self.call_admitted_upstream(permit, now_unix).await
    }

    async fn call_admitted_upstream(
        &self,
        permit: GatewayCallPermit,
        now_unix: i64,
    ) -> Result<CallToolResult, McpError> {
        let gateway = Arc::clone(&self.gateway);
        let mut guard = PermitGuard::new(gateway, permit, now_unix);
        if let Some(plan) = guard.before_hook_plan().map_err(gateway_request_error)? {
            let rewrite_authorizations = self
                .hook_authorizations_for(&plan)
                .await
                .map_err(gateway_request_error)?;
            let schema = guard.tool_input_schema().map_err(gateway_request_error)?;
            let hook_call_context = guard.hook_call_context().map_err(gateway_request_error)?;
            let outcomes = self
                .execute_hook_plan(
                    &plan,
                    &rewrite_authorizations,
                    Some(&schema),
                    Some(&hook_call_context),
                )
                .await;
            let before = guard
                .complete_before(outcomes, &rewrite_authorizations, schema)
                .await
                .map_err(gateway_request_error)?;
            if before.decision == HookBeforeDecision::Deny {
                guard
                    .cancel(unix_now().unwrap_or(now_unix))
                    .await
                    .map_err(gateway_request_error)?;
                return Ok(CallToolResult::error(vec![ContentBlock::text(
                    "Unpin hook policy denied tool call",
                )]));
            }
        }
        let (identity, upstream_name, credential_key_id, arguments) =
            guard.upstream_request().map_err(gateway_request_error)?;
        let authorization = if let Some(key_id) = credential_key_id.clone() {
            let credentials = Arc::clone(&self.credentials);
            let credential_identity = identity.clone();
            tokio::task::spawn_blocking(move || {
                credentials.resolve(&key_id, &credential_identity).map(Some)
            })
            .await
            .map_err(|_| GatewayRuntimeError::CredentialUnavailable)
            .and_then(|resolved| resolved)
        } else {
            Ok(None)
        };
        let authorization = match authorization {
            Ok(authorization) => authorization,
            Err(error) => {
                self.finish_failed_call(&mut guard, &error, unix_now().unwrap_or(now_unix))
                    .await
                    .map_err(gateway_request_error)?;
                return Ok(runtime_tool_error(error));
            }
        };
        let result = self
            .upstreams
            .call_with_message_limit(UpstreamCallRequest {
                identity: &identity,
                credential_key_id: credential_key_id.as_deref(),
                authorization,
                tool_name: &upstream_name,
                arguments,
                timeouts: self.timeouts,
                maximum_message_bytes: gateway_message_limit(&self.gateway),
            })
            .await;
        match result {
            Ok(result) => {
                let bounded = serde_json::to_value(&result).map_err(|_| internal_error())?;
                let plan = guard
                    .plan_after(true, bounded.clone())
                    .await
                    .map_err(gateway_request_error)?;
                let rewrite_authorizations = self
                    .hook_authorizations_for(&plan)
                    .await
                    .map_err(gateway_request_error)?;
                let hook_call_context = guard.hook_call_context().map_err(gateway_request_error)?;
                let outcomes = self
                    .execute_hook_plan(
                        &plan,
                        &rewrite_authorizations,
                        None,
                        Some(&hook_call_context),
                    )
                    .await;
                match guard
                    .finish_with_hooks(
                        true,
                        bounded,
                        outcomes,
                        &rewrite_authorizations,
                        unix_now().unwrap_or(now_unix),
                    )
                    .await
                {
                    Ok(after) => serde_json::from_value(after.result).map_err(|_| internal_error()),
                    Err(GatewayError::ResponseLimitExceeded) => {
                        Ok(CallToolResult::error(vec![ContentBlock::text(
                            "upstream response exceeded gateway limits",
                        )]))
                    }
                    Err(error) => Err(gateway_request_error(error)),
                }
            }
            Err(error) => {
                self.finish_failed_call(&mut guard, &error, unix_now().unwrap_or(now_unix))
                    .await
                    .map_err(gateway_request_error)?;
                Ok(runtime_tool_error(error))
            }
        }
    }
}

struct McpHookActionRequest<'a> {
    hook_call_context: &'a GatewayHookCallContext,
    server_id: &'a str,
    tool_name: &'a str,
    payload: Value,
    chain: HookInvocationChain,
    timeout: Duration,
    maximum_output_bytes: usize,
}

struct HookExecutionBatch {
    outcomes: BTreeMap<String, HookActionOutcome>,
    authorization_ids: BTreeSet<String>,
    plan_binding: String,
}

impl HookExecutionBatch {
    #[cfg(all(test, unix))]
    fn outcomes(&self) -> &BTreeMap<String, HookActionOutcome> {
        &self.outcomes
    }

    fn into_outcomes(
        self,
        rewrite_authorizations: &[HookRewriteAuthorization],
        expected_plan_binding: &str,
    ) -> Result<BTreeMap<String, HookActionOutcome>, GatewayError> {
        if self.authorization_ids == hook_authorization_ids(rewrite_authorizations)
            && self.plan_binding == expected_plan_binding
        {
            Ok(self.outcomes)
        } else {
            Err(GatewayError::HookDispatchIncomplete)
        }
    }
}

fn hook_authorization_ids(rewrite_authorizations: &[HookRewriteAuthorization]) -> BTreeSet<String> {
    rewrite_authorizations
        .iter()
        .map(|authorization| authorization.operation_id().to_string())
        .collect()
}

struct HookExecutionState {
    arguments: Value,
    result: Option<Value>,
    context_bytes: usize,
}

fn apply_hook_outcome_to_execution(
    plan: &HookDispatchPlan,
    step: &HookDispatchStep,
    outcome: &HookActionOutcome,
    rewrite_authorizations: &[HookRewriteAuthorization],
    argument_schema: Option<&Value>,
    execution: &mut HookExecutionState,
) -> bool {
    let handler = step.handler();
    let fail_closed = handler.failure_policy() == HookFailurePolicy::FailClosed;
    match (plan.event_family(), outcome) {
        (HookEventFamily::BeforeTool, HookActionOutcome::Deny) => true,
        (_, HookActionOutcome::Failed) => fail_closed,
        (_, HookActionOutcome::Skipped) => true,
        (HookEventFamily::BeforeTool, HookActionOutcome::RewriteArguments(rewritten)) => {
            if !handler.transformations().argument_rewrite {
                return fail_closed;
            }
            let Ok(request) = HookRewriteRequest::new(
                plan.provider(),
                plan.profile_digest(),
                handler.id(),
                &execution.arguments,
                rewritten,
            ) else {
                return true;
            };
            let authorized = rewrite_authorizations
                .iter()
                .any(|authorization| authorization.authorizes(&request));
            let valid = argument_schema
                .is_some_and(|schema| arguments_match_schema(rewritten, schema))
                && runtime_value_within(rewritten, plan.maximum_payload_bytes());
            if authorized && valid {
                execution.arguments = rewritten.clone();
                false
            } else {
                true
            }
        }
        (HookEventFamily::BeforeTool, HookActionOutcome::ReplaceResult(_)) => fail_closed,
        (
            HookEventFamily::AfterToolSuccess | HookEventFamily::AfterToolFailure,
            HookActionOutcome::ReplaceResult(replacement),
        ) => {
            if !handler.transformations().result_modification {
                return fail_closed;
            }
            let Some(original) = execution.result.as_ref() else {
                return true;
            };
            let Ok(request) = HookRewriteRequest::new_result(
                plan.provider(),
                plan.profile_digest(),
                handler.id(),
                original,
                replacement,
            ) else {
                return true;
            };
            let authorized = rewrite_authorizations
                .iter()
                .any(|authorization| authorization.authorizes(&request));
            if authorized && runtime_value_within(replacement, plan.maximum_payload_bytes()) {
                execution.result = Some(replacement.clone());
                false
            } else {
                fail_closed
            }
        }
        (_, HookActionOutcome::AddContext(value)) => {
            let next_bytes = execution.context_bytes.saturating_add(value.len());
            if handler.transformations().context_injection
                && next_bytes <= plan.maximum_context_bytes()
                && valid_hook_context(value)
            {
                execution.context_bytes = next_bytes;
                false
            } else {
                fail_closed
            }
        }
        (
            HookEventFamily::AfterToolSuccess | HookEventFamily::AfterToolFailure,
            HookActionOutcome::RewriteArguments(_),
        ) => fail_closed,
        (_, HookActionOutcome::Continue | HookActionOutcome::Deny) => false,
        (_, HookActionOutcome::RewriteArguments(_) | HookActionOutcome::ReplaceResult(_)) => {
            fail_closed
        }
    }
}

fn runtime_value_within(value: &Value, maximum_bytes: usize) -> bool {
    serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= maximum_bytes)
}

fn valid_hook_context(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

#[derive(Debug, Clone, Copy)]
enum HookExecutionError {
    Unsupported,
    InvalidInvocation,
    Failed,
    TimedOut,
    OutputLimitExceeded,
    InvalidOutput,
}

async fn execute_hook_action(
    http_client: Option<&reqwest::Client>,
    action: &HookAction,
    payload: &Value,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<HookActionOutcome, HookExecutionError> {
    if timeout.is_zero() || maximum_output_bytes == 0 {
        return Err(HookExecutionError::InvalidInvocation);
    }
    if let Some(command) = action
        .materialize_command()
        .map_err(|_| HookExecutionError::InvalidInvocation)?
    {
        return execute_command_hook(command, payload, timeout, maximum_output_bytes).await;
    }
    if let Some(endpoint) = action.http_endpoint() {
        let client = http_client.ok_or(HookExecutionError::Failed)?;
        return execute_http_hook(client, endpoint, payload, timeout, maximum_output_bytes).await;
    }
    if action.mcp_target().is_some() || action.component_reference().is_some() {
        return Err(HookExecutionError::Unsupported);
    }
    Err(HookExecutionError::Unsupported)
}

async fn execute_command_hook(
    command: unpin_core::hooks::MaterializedHookCommand,
    payload: &Value,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<HookActionOutcome, HookExecutionError> {
    let input = serde_json::to_vec(payload).map_err(|_| HookExecutionError::InvalidInvocation)?;
    if input.len() > maximum_output_bytes {
        return Err(HookExecutionError::InvalidInvocation);
    }
    let mut process = tokio::process::Command::new(&command.executable);
    process
        .args(&command.arguments)
        .current_dir(&command.working_directory)
        .env_clear()
        .envs(command.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = process.spawn().map_err(|_| HookExecutionError::Failed)?;
    let mut stdin = child.stdin.take().ok_or(HookExecutionError::Failed)?;
    let stdout = child.stdout.take().ok_or(HookExecutionError::Failed)?;
    let execution = async {
        let writer = async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        };
        let reader = async move {
            let mut output = Vec::new();
            stdout
                .take(u64::try_from(maximum_output_bytes).unwrap_or(u64::MAX) + 1)
                .read_to_end(&mut output)
                .await?;
            Ok::<_, io::Error>(output)
        };
        let ((), output, status) = tokio::try_join!(writer, reader, child.wait())?;
        Ok::<_, io::Error>((output, status))
    };
    let (output, status) = tokio::time::timeout(timeout, execution)
        .await
        .map_err(|_| HookExecutionError::TimedOut)?
        .map_err(|_| HookExecutionError::Failed)?;
    if !status.success() {
        return Err(HookExecutionError::Failed);
    }
    parse_hook_output(&output, maximum_output_bytes)
}

async fn execute_http_hook(
    client: &reqwest::Client,
    endpoint: &str,
    payload: &Value,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<HookActionOutcome, HookExecutionError> {
    let execution = async {
        let response = client
            .post(endpoint)
            .json(payload)
            .send()
            .await
            .map_err(|_| HookExecutionError::Failed)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > maximum_output_bytes as u64)
        {
            return Err(HookExecutionError::Failed);
        }
        let mut output = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| HookExecutionError::Failed)?;
            if output.len().saturating_add(chunk.len()) > maximum_output_bytes {
                return Err(HookExecutionError::OutputLimitExceeded);
            }
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    };
    let output = tokio::time::timeout(timeout, execution)
        .await
        .map_err(|_| HookExecutionError::TimedOut)??;
    parse_hook_output(&output, maximum_output_bytes)
}

fn parse_hook_output(
    output: &[u8],
    maximum_output_bytes: usize,
) -> Result<HookActionOutcome, HookExecutionError> {
    if output.len() > maximum_output_bytes {
        return Err(HookExecutionError::OutputLimitExceeded);
    }
    let value: Value =
        serde_json::from_slice(output).map_err(|_| HookExecutionError::InvalidOutput)?;
    parse_hook_value(&value)
}

fn parse_hook_value(value: &Value) -> Result<HookActionOutcome, HookExecutionError> {
    let object = value.as_object().ok_or(HookExecutionError::InvalidOutput)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "decision" | "arguments" | "result" | "context"
        )
    }) {
        return Err(HookExecutionError::InvalidOutput);
    }
    let decision = object.get("decision").and_then(Value::as_str);
    if object.get("decision").is_some() && decision.is_none() {
        return Err(HookExecutionError::InvalidOutput);
    }
    if decision == Some("deny") {
        return if object.len() == 1 {
            Ok(HookActionOutcome::Deny)
        } else {
            Err(HookExecutionError::InvalidOutput)
        };
    }
    if !matches!(decision, None | Some("allow" | "continue")) {
        return Err(HookExecutionError::InvalidOutput);
    }
    let transformations = ["arguments", "result", "context"]
        .into_iter()
        .filter(|key| object.contains_key(*key))
        .collect::<Vec<_>>();
    if transformations.len() > 1 {
        return Err(HookExecutionError::InvalidOutput);
    }
    match transformations.first().copied() {
        Some("arguments") => object
            .get("arguments")
            .filter(|value| value.is_object())
            .cloned()
            .map(HookActionOutcome::RewriteArguments)
            .ok_or(HookExecutionError::InvalidOutput),
        Some("result") => Ok(HookActionOutcome::ReplaceResult(
            object.get("result").cloned().unwrap_or(Value::Null),
        )),
        Some("context") => object
            .get("context")
            .and_then(Value::as_str)
            .map(str::to_string)
            .map(HookActionOutcome::AddContext)
            .ok_or(HookExecutionError::InvalidOutput),
        Some(_) => Err(HookExecutionError::InvalidOutput),
        None => Ok(HookActionOutcome::Continue),
    }
}

fn arguments_match_schema(arguments: &Value, schema: &Value) -> bool {
    validate_schema_value(arguments, schema, 0)
}

fn validate_schema_value(value: &Value, schema: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    let Some(schema) = schema.as_object() else {
        return schema.as_bool().unwrap_or(false);
    };
    const SUPPORTED_KEYWORDS: &[&str] = &[
        "$schema",
        "$id",
        "title",
        "description",
        "default",
        "examples",
        "type",
        "const",
        "enum",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "properties",
        "required",
        "additionalProperties",
        "items",
    ];
    if schema
        .keys()
        .any(|keyword| !SUPPORTED_KEYWORDS.contains(&keyword.as_str()))
        || schema.get("enum").is_some_and(|values| !values.is_array())
        || schema
            .get("properties")
            .is_some_and(|properties| !properties.is_object())
        || schema.get("required").is_some_and(|required| {
            required
                .as_array()
                .is_none_or(|values| values.iter().any(|value| !value.is_string()))
        })
        || schema
            .get("additionalProperties")
            .is_some_and(|additional| !additional.is_boolean() && !additional.is_object())
        || ["allOf", "anyOf", "oneOf"]
            .into_iter()
            .any(|keyword| schema.get(keyword).is_some_and(|value| !value.is_array()))
        || schema
            .get("not")
            .is_some_and(|value| !value.is_boolean() && !value.is_object())
        || schema
            .get("items")
            .is_some_and(|value| !value.is_boolean() && !value.is_object())
    {
        return false;
    }
    if schema
        .get("const")
        .is_some_and(|expected| expected != value)
        || schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
    {
        return false;
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array)
        && !all_of
            .iter()
            .all(|schema| validate_schema_value(value, schema, depth + 1))
    {
        return false;
    }
    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array)
        && !any_of
            .iter()
            .any(|schema| validate_schema_value(value, schema, depth + 1))
    {
        return false;
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array)
        && one_of
            .iter()
            .filter(|schema| validate_schema_value(value, schema, depth + 1))
            .take(2)
            .count()
            != 1
    {
        return false;
    }
    if let Some(not) = schema.get("not")
        && validate_schema_value(value, not, depth + 1)
    {
        return false;
    }
    let valid_type = match schema.get("type") {
        None => true,
        Some(Value::String(kind)) => value_matches_type(value, kind),
        Some(Value::Array(kinds)) => {
            !kinds.is_empty()
                && kinds.iter().all(Value::is_string)
                && kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|kind| value_matches_type(value, kind))
        }
        Some(_) => false,
    };
    if !valid_type {
        return false;
    }
    if let Some(object) = value.as_object() {
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|key| !object.contains_key(key))
            })
        {
            return false;
        }
        for (key, value) in object {
            if let Some(property_schema) = properties.get(key) {
                if !validate_schema_value(value, property_schema, depth + 1) {
                    return false;
                }
            } else if let Some(additional) = schema.get("additionalProperties")
                && (additional == &Value::Bool(false)
                    || !validate_schema_value(value, additional, depth + 1))
            {
                return false;
            }
        }
    }
    if let Some(values) = value.as_array()
        && let Some(item_schema) = schema.get("items")
        && !values
            .iter()
            .all(|value| validate_schema_value(value, item_schema, depth + 1))
    {
        return false;
    }
    true
}

fn value_matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

impl ServerHandler for GatewayMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("unpin-gateway", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Search scoped skill metadata, load selected skills lazily, and call only tools exposed by this session profile.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let _list_change = self.list_change_gate.read().await;
        let now_unix = unix_now().map_err(|_| internal_error())?;
        let gateway = Arc::clone(&self.gateway);
        let projected = tokio::task::spawn_blocking(move || gateway.list_tools(now_unix))
            .await
            .map_err(|_| internal_error())?
            .map_err(gateway_request_error)?;
        let mut tools = control_tools()?;
        for tool in projected {
            tools.push(projected_tool(tool)?);
        }
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.call(request).await.map(Into::into)
    }
}

struct PermitGuard {
    gateway: Arc<GatewayService>,
    permit: Arc<StdMutex<GatewayCallPermit>>,
    pending_after_binding: Option<String>,
    fallback_unix: i64,
}

impl PermitGuard {
    fn new(gateway: Arc<GatewayService>, permit: GatewayCallPermit, fallback_unix: i64) -> Self {
        Self {
            gateway,
            permit: Arc::new(StdMutex::new(permit)),
            pending_after_binding: None,
            fallback_unix,
        }
    }

    fn with_permit<T>(
        &self,
        operation: impl FnOnce(&GatewayCallPermit) -> T,
    ) -> Result<T, GatewayError> {
        self.permit
            .lock()
            .map(|permit| operation(&permit))
            .map_err(|_| GatewayError::StatePoisoned)
    }

    fn before_hook_plan(&self) -> Result<Option<HookDispatchPlan>, GatewayError> {
        self.with_permit(|permit| permit.before_hook_plan().cloned())
    }

    fn tool_input_schema(&self) -> Result<Value, GatewayError> {
        self.with_permit(|permit| permit.tool().input_schema.clone())
    }

    fn hook_call_context(&self) -> Result<GatewayHookCallContext, GatewayError> {
        self.with_permit(GatewayCallPermit::hook_call_context)
    }

    fn upstream_request(
        &self,
    ) -> Result<(UpstreamIdentity, String, Option<String>, JsonObject), GatewayError> {
        self.with_permit(|permit| {
            let tool = permit.tool();
            let identity = tool
                .upstream_identity()
                .ok_or(GatewayError::CapabilityUnavailable)?
                .clone();
            let upstream_name = tool
                .upstream_name()
                .ok_or(GatewayError::CapabilityUnavailable)?
                .to_string();
            let credential_key_id = tool.credential_key_id().map(str::to_string);
            let arguments = permit
                .upstream_arguments()?
                .as_object()
                .cloned()
                .ok_or(GatewayError::CapabilityUnavailable)?;
            Ok((identity, upstream_name, credential_key_id, arguments))
        })?
    }

    fn is_active(&self) -> Result<bool, GatewayError> {
        self.with_permit(GatewayCallPermit::is_active)
    }

    async fn complete_before(
        &mut self,
        execution: HookExecutionBatch,
        rewrite_authorizations: &[HookRewriteAuthorization],
        schema: Value,
    ) -> Result<HookBeforeResult, GatewayError> {
        let expected_plan_binding = self
            .before_hook_plan()?
            .as_ref()
            .map(HookDispatchPlan::execution_binding)
            .ok_or(GatewayError::HookDispatchIncomplete)?;
        let outcomes = execution.into_outcomes(rewrite_authorizations, &expected_plan_binding)?;
        let permit = Arc::clone(&self.permit);
        let gateway = Arc::clone(&self.gateway);
        let rewrite_authorizations = rewrite_authorizations.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut permit = permit.lock().map_err(|_| GatewayError::StatePoisoned)?;
            gateway.data_plane().complete_before_hooks(
                &mut permit,
                outcomes,
                &rewrite_authorizations,
                |arguments| arguments_match_schema(arguments, &schema),
            )
        })
        .await
        .map_err(|_| GatewayError::StatePoisoned)?
    }

    async fn plan_after(
        &mut self,
        succeeded: bool,
        response: Value,
    ) -> Result<HookDispatchPlan, GatewayError> {
        let permit = Arc::clone(&self.permit);
        let gateway = Arc::clone(&self.gateway);
        let result = tokio::task::spawn_blocking(move || {
            let mut permit = permit.lock().map_err(|_| GatewayError::StatePoisoned)?;
            gateway
                .data_plane()
                .plan_after_hooks(&mut permit, succeeded, &response)
        })
        .await
        .map_err(|_| GatewayError::StatePoisoned)?;
        if let Ok(plan) = &result {
            self.pending_after_binding = Some(plan.execution_binding());
        }
        result
    }

    async fn finish_with_hooks(
        &mut self,
        succeeded: bool,
        response: Value,
        execution: HookExecutionBatch,
        rewrite_authorizations: &[HookRewriteAuthorization],
        now_unix: i64,
    ) -> Result<HookAfterResult, GatewayError> {
        let expected_plan_binding = self
            .pending_after_binding
            .as_deref()
            .ok_or(GatewayError::HookDispatchIncomplete)?;
        let outcomes = execution.into_outcomes(rewrite_authorizations, expected_plan_binding)?;
        let permit = Arc::clone(&self.permit);
        let gateway = Arc::clone(&self.gateway);
        let rewrite_authorizations = rewrite_authorizations.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            let mut permit = permit.lock().map_err(|_| GatewayError::StatePoisoned)?;
            gateway.data_plane().finish_tool_with_authorized_hooks(
                &mut permit,
                succeeded,
                &response,
                outcomes,
                &rewrite_authorizations,
                now_unix,
            )
        })
        .await
        .map_err(|_| GatewayError::StatePoisoned)?;
        if !self.is_active()? {
            self.pending_after_binding = None;
        }
        result
    }

    async fn cancel(&mut self, now_unix: i64) -> Result<(), GatewayError> {
        self.pending_after_binding = None;
        let permit = Arc::clone(&self.permit);
        let gateway = Arc::clone(&self.gateway);
        tokio::task::spawn_blocking(move || {
            let mut permit = permit.lock().map_err(|_| GatewayError::StatePoisoned)?;
            gateway.data_plane().cancel_tool(&mut permit, now_unix)
        })
        .await
        .map_err(|_| GatewayError::StatePoisoned)?
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        let permit = Arc::clone(&self.permit);
        let gateway = Arc::clone(&self.gateway);
        let now_unix = unix_now().unwrap_or(self.fallback_unix);
        let cleanup = move || {
            let mut permit = permit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if permit.is_active() {
                let _ = gateway.data_plane().cancel_tool(&mut permit, now_unix);
            }
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn_blocking(cleanup));
        } else {
            drop(std::thread::spawn(cleanup));
        }
    }
}

pub async fn serve_gateway_stdio(server: GatewayMcpServer) -> Result<(), GatewayRuntimeError> {
    serve_gateway_io(server, tokio::io::stdin(), tokio::io::stdout()).await
}

pub async fn serve_gateway_io<R, W>(
    server: GatewayMcpServer,
    read: R,
    write: W,
) -> Result<(), GatewayRuntimeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let maximum_message_bytes = gateway_message_limit(&server.gateway);
    let running = server
        .serve(BoundedLineTransport::new(
            read,
            write,
            maximum_message_bytes,
        ))
        .await
        .map_err(|_| GatewayRuntimeError::ServerFailed)?;
    running
        .waiting()
        .await
        .map_err(|_| GatewayRuntimeError::ServerFailed)?;
    Ok(())
}

fn gateway_message_limit(gateway: &GatewayService) -> usize {
    let limits = gateway.limits();
    limits
        .maximum_argument_bytes
        .max(limits.maximum_response_bytes)
        .max(limits.maximum_tool_list_bytes)
        .max(limits.maximum_skill_body_bytes)
        .saturating_add(MCP_ENVELOPE_BYTES)
}

pub async fn notify_list_changed(
    running: &RunningService<RoleServer, GatewayMcpServer>,
) -> Result<(), GatewayRuntimeError> {
    let _list_change = running.service().list_change_gate.write().await;
    running
        .peer()
        .notify_tool_list_changed()
        .await
        .map_err(|_| GatewayRuntimeError::ServerFailed)?;
    let gateway = Arc::clone(&running.service().gateway);
    tokio::task::spawn_blocking(move || gateway.validate_notified_exposure_is_current())
        .await
        .map_err(|_| GatewayRuntimeError::ServerFailed)?
        .map_err(GatewayRuntimeError::Gateway)
}

fn control_tools() -> Result<Vec<Tool>, McpError> {
    [
        json!({
            "name": SEARCH_SKILLS_TOOL,
            "description": "Search metadata for skills selected by this session profile.",
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
    ]
    .into_iter()
    .map(|value| serde_json::from_value(value).map_err(|_| internal_error()))
    .collect()
}

fn projected_tool(projected: ProjectedTool) -> Result<Tool, McpError> {
    let input_schema = json_object(projected.input_schema)?;
    let mut tool = Tool::new_with_raw(
        projected.name,
        projected.description.map(Cow::Owned),
        Arc::new(input_schema),
    );
    tool.title = projected.title;
    tool.output_schema = projected
        .output_schema
        .map(json_object)
        .transpose()?
        .map(Arc::new);
    tool.annotations = projected
        .annotations
        .map(serde_json::from_value::<ToolAnnotations>)
        .transpose()
        .map_err(|_| internal_error())?;
    Ok(tool)
}

fn json_object(value: Value) -> Result<JsonObject, McpError> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(internal_error()),
    }
}

fn compact_arguments<'a>(
    value: &'a Value,
    allowed_keys: &[&str],
) -> Result<&'a JsonObject, McpError> {
    let object = value
        .as_object()
        .ok_or_else(|| McpError::invalid_params("arguments must be an object", None))?;
    if object
        .keys()
        .any(|key| !allowed_keys.contains(&key.as_str()))
    {
        return Err(McpError::invalid_params(
            "arguments contain unknown properties",
            None,
        ));
    }
    Ok(object)
}

fn gateway_request_error(error: GatewayError) -> McpError {
    match error {
        GatewayError::CapabilityUnavailable => McpError::new(
            ErrorCode::METHOD_NOT_FOUND,
            "tool is not exposed in this session",
            None,
        ),
        GatewayError::ArgumentsLimitExceeded => {
            McpError::invalid_params("arguments exceed gateway limits", None)
        }
        _ => internal_error(),
    }
}

fn runtime_tool_error(error: GatewayRuntimeError) -> CallToolResult {
    let reason = match error {
        GatewayRuntimeError::CredentialUnavailable => "upstream authentication is unavailable",
        GatewayRuntimeError::UpstreamCallTimedOut => {
            "upstream call timed out; completion status is unknown"
        }
        GatewayRuntimeError::UpstreamConnectTimedOut => "upstream connection timed out",
        _ => "upstream tool is unavailable",
    };
    CallToolResult::error(vec![ContentBlock::text(reason)])
}

fn runtime_failure_payload(error: &GatewayRuntimeError) -> Value {
    if matches!(error, GatewayRuntimeError::UpstreamCallTimedOut) {
        json!({
            "error": "upstream-call-timeout",
            "completionStatus": "unknown",
            "automaticRetry": false
        })
    } else {
        json!({"error": "upstream-unavailable"})
    }
}

fn internal_error() -> McpError {
    McpError::internal_error("gateway request failed", None)
}

fn unix_now() -> Result<i64, GatewayRuntimeError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayRuntimeError::ClockUnavailable)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| GatewayRuntimeError::ClockUnavailable)
}

#[derive(Debug)]
pub enum GatewayRuntimeError {
    Gateway(GatewayError),
    InvalidUpstreamIdentity,
    CredentialUnavailable,
    InvalidTimeout,
    UpstreamConnectFailed,
    UpstreamConnectTimedOut,
    UpstreamCallFailed,
    UpstreamCallTimedOut,
    ServerFailed,
    ClockUnavailable,
}

impl std::fmt::Display for GatewayRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gateway(_) => formatter.write_str("gateway policy rejected request"),
            Self::InvalidUpstreamIdentity => formatter.write_str("upstream identity is invalid"),
            Self::CredentialUnavailable => {
                formatter.write_str("upstream credential is unavailable")
            }
            Self::InvalidTimeout => formatter.write_str("gateway timeout must be positive"),
            Self::UpstreamConnectFailed => formatter.write_str("upstream connection failed"),
            Self::UpstreamConnectTimedOut => formatter.write_str("upstream connection timed out"),
            Self::UpstreamCallFailed => formatter.write_str("upstream call failed"),
            Self::UpstreamCallTimedOut => formatter.write_str("upstream call timed out"),
            Self::ServerFailed => formatter.write_str("gateway MCP server failed"),
            Self::ClockUnavailable => formatter.write_str("system clock is unavailable"),
        }
    }
}

impl std::error::Error for GatewayRuntimeError {}

impl From<GatewayError> for GatewayRuntimeError {
    fn from(error: GatewayError) -> Self {
        Self::Gateway(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[cfg(unix)]
    use std::collections::BTreeSet;
    #[cfg(unix)]
    use tempfile::TempDir;
    #[cfg(unix)]
    use unpin_core::hooks::{
        HookDispatcher, HookMatcher, HookOwnership, HookPolicy, HookPolicyLimits, HookRouteOwner,
        HookSourceLayer, HookTransformCapabilities,
    };
    #[cfg(unix)]
    use unpin_core::{
        approval::{
            ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims,
            ApprovalVerifier, VerifiedApproval,
        },
        catalog::{
            CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle,
            CapabilityMutability, CapabilityOwnership, CapabilityScope, CapabilityStateEvidence,
            CapabilityTrustRequirements, Catalog, CatalogRecord, ProviderView,
        },
        discovery::DiscoveryLayer,
        gateway::{
            GatewayControlPlane, GatewayExposure, GatewayHookRegistration, GatewayLimits,
            UpstreamToolDescriptor, UpstreamToolRegistration,
        },
        hooks::{HookHandler, HookHandlerSpec},
        profiles::{
            PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope, compile_profile,
        },
        providers::ProviderId,
        sessions::{
            BootstrapRequest, ConnectionClaim, CoverageLevel, IsolationLevel, PinnedExposure,
            PinnedProfile, ProcessEvidence, SessionAuthorityKey, SessionManager,
        },
    };

    fn digest(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    #[cfg(unix)]
    fn verified_approval(expectation: ApprovalExpectation) -> VerifiedApproval {
        let key = ApprovalKey::new([11; 32]);
        let issuer = ApprovalIssuer::new(
            ApprovalKey::new([11; 32]),
            expectation.issuer.clone(),
            expectation.audience.clone(),
        )
        .expect("approval issuer");
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
            .expect("approval receipt");
        ApprovalVerifier::new(key)
            .verify(&receipt, &expectation, 1_100)
            .expect("verified approval")
    }

    #[cfg(unix)]
    #[derive(Debug)]
    struct StaticHookAuthorizations(Vec<HookRewriteAuthorization>);

    #[cfg(unix)]
    impl GatewayHookAuthorizationSource for StaticHookAuthorizations {
        fn authorizations_for(
            &self,
            _plan: &HookDispatchPlan,
        ) -> Result<Vec<HookRewriteAuthorization>, GatewayError> {
            Ok(self.0.clone())
        }
    }

    #[cfg(unix)]
    fn reviewed_runtime_hook(
        id: &str,
        action: HookAction,
        order: i32,
        failure_policy: HookFailurePolicy,
        transformations: HookTransformCapabilities,
        profile_digest: &str,
    ) -> HookHandler {
        let handler = HookHandler::new(HookHandlerSpec {
            id: id.to_string(),
            provider: ProviderId::Codex,
            native_event: "PreToolUse".to_string(),
            event_family: HookEventFamily::BeforeTool,
            matcher: HookMatcher::any(),
            action,
            order,
            timeout_ms: 10_000,
            failure_policy,
            source_layer: HookSourceLayer::Session,
            ownership: HookOwnership::User,
            route_owner: HookRouteOwner::Gateway,
            enabled: true,
            transformations,
        })
        .expect("runtime hook");
        let approval = verified_approval(
            handler
                .trust_approval_expectation(
                    profile_digest,
                    "unpin-ui",
                    "unpin-core",
                    "repository",
                    "workspace",
                    "session",
                )
                .expect("trust expectation"),
        );
        handler
            .review(&approval, profile_digest)
            .expect("review runtime hook")
    }

    #[cfg(unix)]
    fn permit_gateway() -> (TempDir, Arc<GatewayService>, String, i64) {
        permit_gateway_with_identity(
            UpstreamIdentity::streamable_http("cleanup", "https://example.test/mcp").unwrap(),
        )
    }

    #[cfg(unix)]
    fn permit_gateway_with_identity(
        identity: UpstreamIdentity,
    ) -> (TempDir, Arc<GatewayService>, String, i64) {
        let (temp, gateway, name, now_unix, _) = permit_gateway_with_optional_hook(identity, None);
        (temp, gateway, name, now_unix)
    }

    #[cfg(unix)]
    fn permit_gateway_with_hook_identity(
        identity: UpstreamIdentity,
        hook_record: CatalogRecord,
        hook_spec: HookHandlerSpec,
    ) -> (TempDir, Arc<GatewayService>, String, i64, String) {
        permit_gateway_with_optional_hook(identity, Some((hook_record, hook_spec)))
    }

    #[cfg(unix)]
    fn permit_gateway_with_optional_hook(
        identity: UpstreamIdentity,
        hook: Option<(CatalogRecord, HookHandlerSpec)>,
    ) -> (TempDir, Arc<GatewayService>, String, i64, String) {
        let temp = TempDir::new().expect("temporary directory");
        let root = std::fs::canonicalize(temp.path()).expect("canonical root");
        let source_path = root.join("mcp.json");
        std::fs::write(&source_path, "{}").expect("tool source");
        let capability_id = CapabilityId::new("mcp-tool.cleanup").expect("capability id");
        let record = CatalogRecord {
            id: capability_id.clone(),
            kind: CapabilityKind::McpTool,
            display_name: "cleanup".to_string(),
            origin: CanonicalOrigin {
                canonical_key: "cleanup-origin".to_string(),
                source_path: source_path.to_string_lossy().into_owned(),
                state_path: source_path.to_string_lossy().into_owned(),
                scope: CapabilityScope::Repository,
                source_fingerprint: None,
            },
            ownership: CapabilityOwnership::User,
            fingerprint: digest('a'),
            lifecycle: CapabilityLifecycle::discovered(true),
            state_evidence: CapabilityStateEvidence {
                observation: "permit-drop-test".to_string(),
                observed_enabled: true,
            },
            trust_requirements: CapabilityTrustRequirements::default(),
            provider_views: vec![ProviderView {
                provider: ProviderId::Codex,
                discovery_id: "codex:mcp-tool:cleanup".to_string(),
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
        let mut records = vec![record.clone()];
        let mut members = vec![capability_id];
        if let Some((hook_record, _)) = &hook {
            members.push(hook_record.id.clone());
            records.push(hook_record.clone());
        }
        let catalog = Catalog::from_records(records).expect("catalog");
        let profile = compile_profile(
            &ProfileDefinition {
                version: PROFILE_DEFINITION_VERSION,
                id: "cleanup".to_string(),
                display_name: "Cleanup".to_string(),
                description: None,
                members,
                provider_members: BTreeMap::new(),
                supported_providers: std::collections::BTreeSet::new(),
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
        let registration = UpstreamToolRegistration {
            registration_id: "cleanup-registration".to_string(),
            capability_id: record.id.clone(),
            capability_fingerprint: record.fingerprint.clone(),
            provider: ProviderId::Codex,
            identity,
            credential: None,
            descriptor: UpstreamToolDescriptor {
                name: "cleanup".to_string(),
                title: None,
                description: None,
                input_schema: json!({"type": "object"}),
                output_schema: None,
                annotations: None,
                execution: None,
            },
        };
        let limits = GatewayLimits::default();
        let exposure = if let Some((hook_record, hook_spec)) = hook {
            let handler = HookHandler::new(hook_spec).expect("hook handler");
            let approval = verified_approval(
                handler
                    .trust_approval_expectation(
                        &profile.digest,
                        "unpin-ui",
                        "unpin-core",
                        "repository",
                        "workspace",
                        "session",
                    )
                    .expect("hook trust expectation"),
            );
            let handler = handler
                .review(&approval, &profile.digest)
                .expect("review hook handler");
            GatewayExposure::compile_with_hooks(
                pinned.clone(),
                ProviderId::Codex,
                &catalog,
                Some(&profile),
                vec![registration],
                vec![GatewayHookRegistration {
                    capability_id: hook_record.id,
                    capability_fingerprint: hook_record.fingerprint,
                    provider: ProviderId::Codex,
                    handler,
                }],
                limits,
            )
        } else {
            GatewayExposure::compile(
                pinned.clone(),
                ProviderId::Codex,
                &catalog,
                Some(&profile),
                vec![registration],
                limits,
            )
        }
        .expect("exposure");
        let manager =
            SessionManager::with_authority_key(&root, SessionAuthorityKey::new([0x53; 32]));
        let now_unix = unix_now().expect("clock");
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repository".to_string(),
            workspace_key: "workspace".to_string(),
            workspace_revision: Some(digest('1')),
            exposure: pinned,
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "permit-drop-test".to_string(),
            },
            connection_scope_id: "permit-drop-connection".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::from(["permit-drop-resource".to_string()]),
            lease_expires_at_unix: now_unix + 600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "permit-drop-owner".to_string(),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let authority = manager
            .prepare_bootstrap(request, now_unix)
            .expect("prepare bootstrap");
        let session = manager
            .claim_bootstrap(&authority, &claim, now_unix)
            .expect("claim bootstrap");
        let control =
            GatewayControlPlane::new(manager, session.handle, limits.maximum_concurrent_calls)
                .expect("control plane");
        let gateway =
            Arc::new(GatewayService::new(control, exposure, limits).expect("gateway service"));
        let name = gateway.list_tools(now_unix).unwrap()[0].name.clone();
        (temp, gateway, name, now_unix, profile.digest)
    }

    #[cfg(unix)]
    async fn spawn_hook_mcp_fixture()
    -> (String, Arc<Mutex<Vec<Value>>>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("MCP fixture listener");
        let address = listener.local_addr().expect("MCP fixture address");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fixture_calls = Arc::clone(&calls);
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.expect("accept MCP request");
                let calls = Arc::clone(&fixture_calls);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let header_end = loop {
                        let mut chunk = [0_u8; 4096];
                        let read = socket.read(&mut chunk).await.expect("read MCP request");
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if let Some(position) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break position + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.split_once(':').and_then(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().expect("content length"))
                            })
                        })
                        .unwrap_or_default();
                    while request.len().saturating_sub(header_end) < content_length {
                        let mut chunk = [0_u8; 4096];
                        let read = socket.read(&mut chunk).await.expect("read MCP body");
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }
                    let message: Value =
                        serde_json::from_slice(&request[header_end..header_end + content_length])
                            .expect("MCP request JSON");
                    let Some(request_id) = message.get("id").cloned() else {
                        socket
                            .write_all(
                                b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await
                            .expect("write MCP notification response");
                        return;
                    };
                    let result = match message.get("method").and_then(Value::as_str) {
                        Some("initialize") => json!({
                            "protocolVersion": message["params"]["protocolVersion"],
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "hook-fixture", "version": "1"}
                        }),
                        Some("tools/call") => {
                            calls
                                .lock()
                                .await
                                .push(message["params"]["arguments"].clone());
                            if let Some(delay_ms) =
                                message["params"]["arguments"]["delayMs"].as_u64()
                            {
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            }
                            json!({
                                "content": [{"type": "text", "text": "continue"}],
                                "structuredContent": {"decision": "continue"}
                            })
                        }
                        _ => json!({}),
                    };
                    let body = serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": result
                    }))
                    .expect("MCP response JSON");
                    socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("write MCP response headers");
                    socket
                        .write_all(&body)
                        .await
                        .expect("write MCP response body");
                });
            }
        });
        (format!("http://{address}/mcp"), calls, task)
    }

    #[tokio::test]
    async fn bounded_stdio_transport_rejects_oversized_lines_before_parsing() {
        let (mut peer, transport_io) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(transport_io);
        let mut transport = BoundedLineTransport::<RoleServer, _, _>::new(read, write, 4);
        peer.write_all(b"12345\n")
            .await
            .expect("write oversized line");

        assert!(transport.receive().await.is_none());
    }

    #[tokio::test]
    async fn bounded_stdio_transport_closes_after_repeated_malformed_frames() {
        let (mut peer, transport_io) = tokio::io::duplex(128);
        let (read, write) = tokio::io::split(transport_io);
        let mut transport = BoundedLineTransport::<RoleServer, _, _>::new(read, write, 32);
        peer.write_all(b"x\ny\nz\n")
            .await
            .expect("write malformed frames");

        assert!(transport.receive().await.is_none());
    }

    #[test]
    fn rotated_bearer_tokens_get_distinct_connection_fingerprints() {
        let identity =
            UpstreamIdentity::streamable_http("server", "https://example.test/mcp").unwrap();
        let first = BoundBearerToken::new("credential", &identity, "first-secret").unwrap();
        let second = BoundBearerToken::new("credential", &identity, "second-secret").unwrap();
        let pool = McpUpstreamPool::default();

        assert_ne!(
            first.connection_fingerprint(&pool.fingerprint_state),
            second.connection_fingerprint(&pool.fingerprint_state)
        );
    }

    #[test]
    fn rotated_credential_evicts_prior_connection_without_cross_identity_effects() {
        let old = UpstreamConnectionKey {
            identity_digest: digest('a'),
            credential_key_id: Some("credential".to_string()),
            credential_fingerprint: Some("old".to_string()),
            maximum_message_bytes: 1024,
        };
        let replacement = UpstreamConnectionKey {
            credential_fingerprint: Some("new".to_string()),
            ..old.clone()
        };
        let other_identity = UpstreamConnectionKey {
            identity_digest: digest('b'),
            ..old.clone()
        };
        let mut clients = BTreeMap::from([(old.clone(), "old"), (other_identity.clone(), "other")]);

        evict_replaced_connection(&mut clients, &replacement);

        assert!(!clients.contains_key(&old));
        assert_eq!(clients.get(&other_identity), Some(&"other"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn permit_guard_drop_releases_admission_off_reactor() {
        let (_temp, gateway, name, now_unix) = permit_gateway();
        let permit = gateway
            .data_plane()
            .admit_tool(&name, &json!({}), now_unix + 1)
            .expect("admit call");
        assert_eq!(gateway.control_plane().status().unwrap().in_flight_calls, 1);

        drop(PermitGuard::new(Arc::clone(&gateway), permit, now_unix + 2));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status_gateway = Arc::clone(&gateway);
                let in_flight = tokio::task::spawn_blocking(move || {
                    status_gateway
                        .control_plane()
                        .status()
                        .map(|status| status.in_flight_calls)
                })
                .await
                .expect("status task")
                .expect("status");
                if in_flight == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop cleanup timeout");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn permit_guard_reuses_after_plan_binding_after_failed_finish() {
        let (temp, gateway, name, now_unix) = permit_gateway();
        let permit = gateway
            .data_plane()
            .admit_tool(&name, &json!({}), now_unix + 1)
            .expect("admit call");
        let session_id = gateway.control_plane().status().unwrap().session_id;
        let lease_path = unpin_core::config::get_session_lease_path(temp.path(), &session_id);
        let lease = std::fs::read(&lease_path).expect("read session lease");
        let response = json!({"ok": true});
        let mut guard = PermitGuard::new(Arc::clone(&gateway), permit, now_unix + 2);
        let plan = guard
            .plan_after(true, response.clone())
            .await
            .expect("plan after hooks");
        let plan_binding = plan.execution_binding();

        std::fs::remove_file(&lease_path).expect("remove session lease");
        assert!(
            guard
                .finish_with_hooks(
                    true,
                    response.clone(),
                    HookExecutionBatch {
                        outcomes: BTreeMap::new(),
                        authorization_ids: BTreeSet::new(),
                        plan_binding: plan_binding.clone(),
                    },
                    &[],
                    now_unix + 3,
                )
                .await
                .is_err()
        );
        assert!(guard.is_active().expect("permit status"));
        assert!(matches!(
            guard.plan_after(true, response.clone()).await,
            Err(GatewayError::HookDispatchIncomplete)
        ));

        std::fs::write(&lease_path, lease).expect("restore session lease");
        guard
            .finish_with_hooks(
                true,
                response,
                HookExecutionBatch {
                    outcomes: BTreeMap::new(),
                    authorization_ids: BTreeSet::new(),
                    plan_binding,
                },
                &[],
                now_unix + 4,
            )
            .await
            .expect("finish with retained plan binding");
        assert!(!guard.is_active().expect("permit status"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn permit_guard_drop_releases_admission_after_blocking_step_returns() {
        let (_temp, gateway, name, now_unix) = permit_gateway();
        let permit = gateway
            .data_plane()
            .admit_tool(&name, &json!({}), now_unix + 1)
            .expect("admit call");
        let guard = PermitGuard::new(Arc::clone(&gateway), permit, now_unix + 2);
        let permit_slot = Arc::clone(&guard.permit);
        let locked = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let blocking_step = {
            let locked = Arc::clone(&locked);
            let release = Arc::clone(&release);
            tokio::task::spawn_blocking(move || {
                let _permit = permit_slot.lock().expect("permit slot");
                locked.wait();
                release.wait();
            })
        };
        locked.wait();

        drop(guard);
        release.wait();
        blocking_step.await.expect("blocking step");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status_gateway = Arc::clone(&gateway);
                let in_flight = tokio::task::spawn_blocking(move || {
                    status_gateway
                        .control_plane()
                        .status()
                        .map(|status| status.in_flight_calls)
                })
                .await
                .expect("status task")
                .expect("status");
                if in_flight == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared permit cleanup timeout");
    }

    #[test]
    fn hook_output_and_argument_schema_parsing_fail_closed() {
        assert_eq!(
            parse_hook_output(br#"{"decision":"continue"}"#, 128).unwrap(),
            HookActionOutcome::Continue
        );
        assert!(matches!(
            parse_hook_output(br#"{"decision":"deny","context":"hidden"}"#, 128),
            Err(HookExecutionError::InvalidOutput)
        ));
        assert!(matches!(
            parse_hook_output(br#"{"decision":"continue","unknown":true}"#, 128),
            Err(HookExecutionError::InvalidOutput)
        ));

        let schema = json!({
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": false
        });
        assert!(arguments_match_schema(&json!({"path": "safe"}), &schema));
        assert!(!arguments_match_schema(&json!({"path": 7}), &schema));
        assert!(!arguments_match_schema(
            &json!({"path": "safe", "extra": true}),
            &schema
        ));
        assert!(!arguments_match_schema(
            &json!({"path": "safe"}),
            &json!({
                "type": "object",
                "properties": {"path": {"type": "string", "pattern": "^restricted/"}}
            })
        ));
        assert!(!arguments_match_schema(
            &json!({"path": "safe"}),
            &json!({"$ref": "#/$defs/input"})
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn structured_command_hook_uses_owned_environment_and_bounded_output() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temporary directory");
        let script = temp.path().join("hook.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nif [ -n \"${HOME:-}\" ]; then exit 7; fi\n/bin/cat >/dev/null\nprintf '{\"decision\":\"continue\"}'\n",
        )
        .expect("write hook");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("make hook executable");
        let action = HookAction::structured_command(
            &script,
            Vec::new(),
            temp.path(),
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("structured hook");

        let outcome = execute_hook_action(
            None,
            &action,
            &json!({"value": 1}),
            Duration::from_secs(10),
            128,
        )
        .await
        .expect("execute hook");

        assert_eq!(outcome, HookActionOutcome::Continue);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_before_hook_deny_skips_later_side_effects() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temporary directory");
        let deny = temp.path().join("deny.sh");
        std::fs::write(
            &deny,
            "#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"decision\":\"deny\"}'\n",
        )
        .expect("deny hook");
        std::fs::set_permissions(&deny, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = temp.path().join("later-ran");
        let later = temp.path().join("later.sh");
        std::fs::write(
            &later,
            "#!/bin/sh\n/bin/cat >/dev/null\nprintf touched > \"$1\"\nprintf '{\"decision\":\"continue\"}'\n",
        )
        .expect("later hook");
        std::fs::set_permissions(&later, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = digest('a');
        let handlers = vec![
            reviewed_runtime_hook(
                "deny",
                HookAction::structured_command(
                    &deny,
                    Vec::new(),
                    temp.path(),
                    BTreeMap::new(),
                    Vec::new(),
                )
                .unwrap(),
                0,
                HookFailurePolicy::FailClosed,
                HookTransformCapabilities::none(),
                &profile,
            ),
            reviewed_runtime_hook(
                "later",
                HookAction::structured_command(
                    &later,
                    vec![marker.to_string_lossy().into_owned()],
                    temp.path(),
                    BTreeMap::new(),
                    Vec::new(),
                )
                .unwrap(),
                1,
                HookFailurePolicy::ContinueDegraded,
                HookTransformCapabilities::none(),
                &profile,
            ),
        ];
        let dispatcher = HookDispatcher::new(Arc::new(
            HookPolicy::compile(
                ProviderId::Codex,
                &profile,
                handlers,
                HookPolicyLimits::default(),
            )
            .unwrap(),
        ));
        let plan = dispatcher
            .plan_before(
                "shell",
                &json!({}),
                HookRouteOwner::Gateway,
                &HookInvocationChain::default(),
            )
            .unwrap();
        let plan_binding = plan.execution_binding();
        let (_state, gateway, _name, _now) = permit_gateway();
        let server = GatewayMcpServer::new(
            gateway,
            Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts::default(),
        );

        let schema = json!({"type": "object"});
        let execution = server
            .execute_hook_plan(&plan, &[], Some(&schema), None)
            .await;
        let outcomes = execution.outcomes();

        assert_eq!(outcomes["deny"], HookActionOutcome::Deny);
        assert_eq!(outcomes["later"], HookActionOutcome::Skipped);
        assert!(!marker.exists());
        let outcomes = execution.into_outcomes(&[], &plan_binding).unwrap();
        let completed = dispatcher
            .complete_before(plan, outcomes, &[], |_| true)
            .expect("complete denied plan");
        assert_eq!(completed.decision, HookBeforeDecision::Deny);
        assert!(completed.failures.iter().any(|failure| {
            failure.handler_id == "later"
                && failure.reason == unpin_core::hooks::HookFailureReason::SkippedAfterTerminal
                && !failure.fail_closed
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_hook_pipeline_passes_approved_rewrite_to_later_handler() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("temporary directory");
        let rewrite = temp.path().join("rewrite.sh");
        std::fs::write(
            &rewrite,
            "#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"arguments\":{\"path\":\"rewritten\"}}'\n",
        )
        .expect("rewrite hook");
        std::fs::set_permissions(&rewrite, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = temp.path().join("observed-payload");
        let observe = temp.path().join("observe.sh");
        std::fs::write(
            &observe,
            "#!/bin/sh\npayload=$(/bin/cat)\ncase \"$payload\" in *rewritten*) ;; *) exit 9 ;; esac\nprintf '%s' \"$payload\" > \"$1\"\nprintf '{\"decision\":\"continue\"}'\n",
        )
        .expect("observe hook");
        std::fs::set_permissions(&observe, std::fs::Permissions::from_mode(0o700)).unwrap();
        let profile = digest('b');
        let handlers = vec![
            reviewed_runtime_hook(
                "rewrite",
                HookAction::structured_command(
                    &rewrite,
                    Vec::new(),
                    temp.path(),
                    BTreeMap::new(),
                    Vec::new(),
                )
                .unwrap(),
                0,
                HookFailurePolicy::FailClosed,
                HookTransformCapabilities {
                    argument_rewrite: true,
                    result_modification: false,
                    context_injection: false,
                },
                &profile,
            ),
            reviewed_runtime_hook(
                "observe",
                HookAction::structured_command(
                    &observe,
                    vec![marker.to_string_lossy().into_owned()],
                    temp.path(),
                    BTreeMap::new(),
                    Vec::new(),
                )
                .unwrap(),
                1,
                HookFailurePolicy::FailClosed,
                HookTransformCapabilities::none(),
                &profile,
            ),
        ];
        let dispatcher = HookDispatcher::new(Arc::new(
            HookPolicy::compile(
                ProviderId::Codex,
                &profile,
                handlers,
                HookPolicyLimits::default(),
            )
            .unwrap(),
        ));
        let original = json!({"path": "original"});
        let rewritten = json!({"path": "rewritten"});
        let plan = dispatcher
            .plan_before(
                "read",
                &original,
                HookRouteOwner::Gateway,
                &HookInvocationChain::default(),
            )
            .unwrap();
        let plan_binding = plan.execution_binding();
        let request = HookRewriteRequest::new(
            ProviderId::Codex,
            &profile,
            "rewrite",
            &original,
            &rewritten,
        )
        .unwrap();
        let approval = verified_approval(request.approval_expectation(
            "unpin-ui",
            "unpin-core",
            "repository",
            "workspace",
            "session",
        ));
        let authorizations =
            vec![HookRewriteAuthorization::from_verified(&request, &approval).unwrap()];
        let schema = json!({
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
            "additionalProperties": false
        });
        let (_state, gateway, _name, _now) = permit_gateway();
        let server = GatewayMcpServer::new(
            gateway,
            Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts::default(),
        );

        let mismatched = server
            .execute_hook_plan(&plan, &[], Some(&schema), None)
            .await;
        assert!(matches!(
            mismatched.into_outcomes(&authorizations, &plan_binding),
            Err(GatewayError::HookDispatchIncomplete)
        ));
        assert!(!marker.exists());

        let execution = server
            .execute_hook_plan(&plan, &authorizations, Some(&schema), None)
            .await;
        let outcomes = execution.outcomes();

        assert_eq!(
            outcomes["rewrite"],
            HookActionOutcome::RewriteArguments(rewritten)
        );
        assert_eq!(outcomes["observe"], HookActionOutcome::Continue);
        assert!(
            std::fs::read_to_string(marker)
                .unwrap()
                .contains("rewritten")
        );
        let outcomes = execution
            .into_outcomes(&authorizations, &plan_binding)
            .unwrap();
        let completed = dispatcher
            .complete_before(plan, outcomes, &authorizations, |arguments| {
                arguments_match_schema(arguments, &schema)
            })
            .expect("complete rewritten plan");
        assert_eq!(completed.decision, HookBeforeDecision::Allow);
        assert_eq!(completed.arguments, json!({"path": "rewritten"}));
    }

    #[tokio::test]
    async fn http_hook_timeout_covers_response_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("hook listener");
        let address = listener.local_addr().expect("hook address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept hook request");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.expect("read hook request");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write hook headers");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let client = build_hardened_http_client().expect("hook HTTP client");
        let outcome = execute_http_hook(
            &client,
            &format!("http://{address}/hook"),
            &json!({}),
            Duration::from_millis(50),
            128,
        )
        .await;
        server.abort();

        assert!(matches!(outcome, Err(HookExecutionError::TimedOut)));
    }

    #[tokio::test]
    async fn repeated_http_hooks_reuse_one_hardened_client_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        async fn read_request(socket: &mut tokio::net::TcpStream) -> io::Result<bool> {
            let mut request = Vec::with_capacity(1024);
            loop {
                if let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    let headers = std::str::from_utf8(&request[..header_end])
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    let content_length = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find_map(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end + 4 + content_length {
                        return Ok(true);
                    }
                }
                let mut chunk = [0_u8; 1024];
                let read = socket.read(&mut chunk).await?;
                if read == 0 {
                    return if request.is_empty() {
                        Ok(false)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "HTTP hook request ended before its declared body",
                        ))
                    };
                }
                request.extend_from_slice(&chunk[..read]);
            }
        }

        async fn serve_connection(mut socket: tokio::net::TcpStream) -> io::Result<()> {
            const BODY: &[u8] = br#"{"decision":"continue"}"#;
            while read_request(&mut socket).await? {
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            BODY.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                socket.write_all(BODY).await?;
            }
            Ok(())
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("hook listener");
        let address = listener.local_addr().expect("hook address");
        let connections = Arc::new(AtomicUsize::new(0));
        let observed_connections = Arc::clone(&connections);
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.expect("accept hook request");
                observed_connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    serve_connection(socket)
                        .await
                        .expect("serve hook connection");
                });
            }
        });
        let client = build_hardened_http_client().expect("hook HTTP client");
        let action =
            HookAction::http(format!("http://{address}/hook")).expect("local HTTP hook action");

        for _ in 0..2 {
            let outcome = execute_hook_action(
                Some(&client),
                &action,
                &json!({}),
                Duration::from_secs(2),
                128,
            )
            .await
            .expect("execute HTTP hook");
            assert_eq!(outcome, HookActionOutcome::Continue);
        }
        server.abort();

        assert_eq!(connections.load(Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upstream_timeout_runs_after_hook_with_unknown_completion_and_releases_permit() {
        use std::os::unix::fs::PermissionsExt;

        let (endpoint, calls, fixture) = spawn_hook_mcp_fixture().await;
        let hook_temp = TempDir::new().expect("hook temporary directory");
        let marker = hook_temp.path().join("after-timeout.json");
        let script = hook_temp.path().join("after-timeout.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\npayload=$(/bin/cat)\nprintf '%s' \"$payload\" > \"$1\"\nprintf '{\"decision\":\"continue\"}'\n",
        )
        .expect("write timeout hook");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("make timeout hook executable");
        let hook_id = CapabilityId::new("hook.after-timeout").expect("hook capability id");
        let hook_record = CatalogRecord {
            id: hook_id,
            kind: CapabilityKind::Hook,
            display_name: "After timeout".to_string(),
            origin: CanonicalOrigin {
                canonical_key: "after-timeout-hook-origin".to_string(),
                source_path: script.to_string_lossy().into_owned(),
                state_path: script.to_string_lossy().into_owned(),
                scope: CapabilityScope::Repository,
                source_fingerprint: None,
            },
            ownership: CapabilityOwnership::User,
            fingerprint: digest('c'),
            lifecycle: CapabilityLifecycle::discovered(true),
            state_evidence: CapabilityStateEvidence {
                observation: "timeout-hook-test".to_string(),
                observed_enabled: true,
            },
            trust_requirements: CapabilityTrustRequirements::default(),
            provider_views: vec![ProviderView {
                provider: ProviderId::Codex,
                discovery_id: "codex:hook:after-timeout".to_string(),
                layer: DiscoveryLayer::Project,
                enabled: true,
                mutability: CapabilityMutability::ReadWrite,
                source_path: script.to_string_lossy().into_owned(),
                state_path: script.to_string_lossy().into_owned(),
                source_fingerprint: None,
            }],
            dependencies: Vec::new(),
            contributions: Vec::new(),
            contributed_by: None,
            atomic_unknown_contributions: false,
            tool_namespace: None,
            hook_conflict_key: None,
        };
        let hook_spec = HookHandlerSpec {
            id: "after-timeout".to_string(),
            provider: ProviderId::Codex,
            native_event: "PostToolUseFailure".to_string(),
            event_family: HookEventFamily::AfterToolFailure,
            matcher: HookMatcher::any(),
            action: HookAction::structured_command(
                &script,
                vec![marker.to_string_lossy().into_owned()],
                hook_temp.path(),
                BTreeMap::new(),
                Vec::new(),
            )
            .expect("timeout hook action"),
            order: 0,
            timeout_ms: 2_000,
            failure_policy: HookFailurePolicy::FailClosed,
            source_layer: HookSourceLayer::Session,
            ownership: HookOwnership::User,
            route_owner: HookRouteOwner::Gateway,
            enabled: true,
            transformations: HookTransformCapabilities::none(),
        };
        let identity =
            UpstreamIdentity::streamable_http("cleanup", endpoint).expect("upstream identity");
        let (_temp, gateway, name, now_unix, _profile_digest) =
            permit_gateway_with_hook_identity(identity, hook_record, hook_spec);
        let server = GatewayMcpServer::new(
            Arc::clone(&gateway),
            Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(2),
                call: Duration::from_millis(50),
            },
        );

        let result = server
            .call_upstream(&name, json!({"delayMs": 250}), now_unix)
            .await
            .expect("timeout is returned as tool error");
        fixture.abort();

        assert_eq!(result.is_error, Some(true));
        let encoded = serde_json::to_value(&result).expect("timeout result JSON");
        assert_eq!(
            encoded["content"][0]["text"],
            "upstream call timed out; completion status is unknown"
        );
        assert_eq!(calls.lock().await.len(), 1);
        let hook_payload: Value =
            serde_json::from_slice(&std::fs::read(&marker).expect("timeout after-hook payload"))
                .expect("timeout after-hook JSON");
        assert_eq!(hook_payload["result"]["completionStatus"], "unknown");
        assert_eq!(hook_payload["result"]["automaticRetry"], false);
        assert_eq!(gateway.control_plane().status().unwrap().in_flight_calls, 0);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn live_gateway_threads_verified_rewrite_authorizations_through_upstream_call() {
        use std::os::unix::fs::PermissionsExt;

        let (endpoint, calls, fixture) = spawn_hook_mcp_fixture().await;
        let hook_temp = TempDir::new().expect("hook temporary directory");
        let script = hook_temp.path().join("rewrite.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"arguments\":{\"value\":\"rewritten\"}}'\n",
        )
        .expect("rewrite hook");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let hook_id = CapabilityId::new("hook.rewrite").unwrap();
        let hook_record = CatalogRecord {
            id: hook_id,
            kind: CapabilityKind::Hook,
            display_name: "Rewrite".to_string(),
            origin: CanonicalOrigin {
                canonical_key: "rewrite-hook-origin".to_string(),
                source_path: script.to_string_lossy().into_owned(),
                state_path: script.to_string_lossy().into_owned(),
                scope: CapabilityScope::Repository,
                source_fingerprint: None,
            },
            ownership: CapabilityOwnership::User,
            fingerprint: digest('b'),
            lifecycle: CapabilityLifecycle::discovered(true),
            state_evidence: CapabilityStateEvidence {
                observation: "rewrite-hook-test".to_string(),
                observed_enabled: true,
            },
            trust_requirements: CapabilityTrustRequirements::default(),
            provider_views: vec![ProviderView {
                provider: ProviderId::Codex,
                discovery_id: "codex:hook:rewrite".to_string(),
                layer: DiscoveryLayer::Project,
                enabled: true,
                mutability: CapabilityMutability::ReadWrite,
                source_path: script.to_string_lossy().into_owned(),
                state_path: script.to_string_lossy().into_owned(),
                source_fingerprint: None,
            }],
            dependencies: Vec::new(),
            contributions: Vec::new(),
            contributed_by: None,
            atomic_unknown_contributions: false,
            tool_namespace: None,
            hook_conflict_key: None,
        };
        let hook_spec = HookHandlerSpec {
            id: "rewrite-hook".to_string(),
            provider: ProviderId::Codex,
            native_event: "PreToolUse".to_string(),
            event_family: HookEventFamily::BeforeTool,
            matcher: HookMatcher::any(),
            action: HookAction::structured_command(
                &script,
                Vec::new(),
                hook_temp.path(),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap(),
            order: 0,
            timeout_ms: 2_000,
            failure_policy: HookFailurePolicy::FailClosed,
            source_layer: HookSourceLayer::Session,
            ownership: HookOwnership::User,
            route_owner: HookRouteOwner::Gateway,
            enabled: true,
            transformations: HookTransformCapabilities {
                argument_rewrite: true,
                result_modification: false,
                context_injection: false,
            },
        };
        let identity =
            UpstreamIdentity::streamable_http("cleanup", endpoint).expect("upstream identity");
        let (_temp, gateway, name, now_unix, profile_digest) =
            permit_gateway_with_hook_identity(identity, hook_record, hook_spec);
        let original = json!({"value": "original"});
        let rewritten = json!({"value": "rewritten"});
        let request = HookRewriteRequest::new(
            ProviderId::Codex,
            &profile_digest,
            "rewrite-hook",
            &original,
            &rewritten,
        )
        .unwrap();
        let approval = verified_approval(request.approval_expectation(
            "unpin-ui",
            "unpin-core",
            "repository",
            "workspace",
            "session",
        ));
        let authorizations =
            vec![HookRewriteAuthorization::from_verified(&request, &approval).unwrap()];
        let server = GatewayMcpServer::new(
            Arc::clone(&gateway),
            Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(2),
                call: Duration::from_secs(2),
            },
        )
        .with_hook_authorization_source(Arc::new(StaticHookAuthorizations(authorizations)));

        let result = server
            .call_upstream(&name, original, now_unix)
            .await
            .expect("authorized gateway call");
        fixture.abort();

        assert_ne!(result.is_error, Some(true));
        assert_eq!(calls.lock().await.as_slice(), &[rewritten]);
        assert_eq!(gateway.control_plane().status().unwrap().in_flight_calls, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mcp_hook_action_resolves_only_selected_target_and_releases_nested_admission() {
        let (endpoint, _calls, fixture) = spawn_hook_mcp_fixture().await;
        let identity =
            UpstreamIdentity::streamable_http("cleanup", endpoint).expect("MCP hook identity");
        let (_temp, gateway, name, now_unix) = permit_gateway_with_identity(identity);
        let mut outer = gateway
            .data_plane()
            .admit_tool(&name, &json!({}), now_unix)
            .expect("outer call admission");
        let hook_call_context = outer.hook_call_context();
        let server = GatewayMcpServer::new(
            Arc::clone(&gateway),
            Arc::new(NoGatewayCredentials),
            GatewayRuntimeTimeouts {
                connect: Duration::from_secs(2),
                call: Duration::from_secs(2),
            },
        );

        let outcome = server
            .execute_mcp_hook_action(McpHookActionRequest {
                hook_call_context: &hook_call_context,
                server_id: "cleanup",
                tool_name: "cleanup",
                payload: json!({"toolName": "original"}),
                chain: HookInvocationChain::default(),
                timeout: Duration::from_secs(2),
                maximum_output_bytes: 1024,
            })
            .await
            .expect("MCP hook action");
        fixture.abort();

        assert_eq!(outcome, HookActionOutcome::Continue);
        assert_eq!(gateway.control_plane().status().unwrap().in_flight_calls, 1);
        gateway
            .data_plane()
            .cancel_tool(&mut outer, now_unix + 1)
            .expect("outer call cleanup");
        assert_eq!(gateway.control_plane().status().unwrap().in_flight_calls, 0);
    }
}
