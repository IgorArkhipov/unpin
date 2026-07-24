use std::{borrow::Cow, collections::HashMap, fmt, sync::Arc};

use futures::{StreamExt, stream::BoxStream};
use http::{HeaderName, HeaderValue, header::WWW_AUTHENTICATE};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rmcp::{
    model::{ClientJsonRpcMessage, JsonRpcMessage, ServerJsonRpcMessage},
    transport::{
        common::http_header::{
            EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
        },
        streamable_http_client::{
            AuthRequiredError, InsufficientScopeError, SseError, StreamableHttpClient,
            StreamableHttpError, StreamableHttpPostResponse,
        },
    },
};
use sse_stream::{Sse, SseStream};

#[derive(Debug)]
pub(super) enum BoundedHttpClientError {
    Request(reqwest::Error),
    ResponseLimitExceeded,
}

impl fmt::Display for BoundedHttpClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => write!(formatter, "HTTP request failed: {error}"),
            Self::ResponseLimitExceeded => {
                formatter.write_str("HTTP response exceeded configured limit")
            }
        }
    }
}

impl std::error::Error for BoundedHttpClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::ResponseLimitExceeded => None,
        }
    }
}

#[derive(Clone)]
pub(super) struct BoundedHttpClient {
    client: reqwest::Client,
    maximum_message_bytes: usize,
}

impl BoundedHttpClient {
    pub(super) fn new(maximum_message_bytes: usize) -> Result<Self, BoundedHttpClientError> {
        if maximum_message_bytes == 0 {
            return Err(BoundedHttpClientError::ResponseLimitExceeded);
        }
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(BoundedHttpClientError::Request)?;
        Ok(Self {
            client,
            maximum_message_bytes,
        })
    }

    fn apply_custom_headers(
        &self,
        mut builder: reqwest::RequestBuilder,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<reqwest::RequestBuilder, StreamableHttpError<BoundedHttpClientError>> {
        for (name, value) in custom_headers {
            validate_custom_header(&name).map_err(StreamableHttpError::ReservedHeaderConflict)?;
            builder = builder.header(name, value);
        }
        Ok(builder)
    }

    fn sse_stream(&self, response: reqwest::Response) -> BoxStream<'static, Result<Sse, SseError>> {
        // Limit each protocol event, not aggregate connection bytes: valid MCP
        // notification streams may be long-lived. Outer connect/call timeouts
        // bound request lifetime while this keeps parser memory bounded.
        let mut limiter = SseEventLimiter::new(self.maximum_message_bytes);
        let bytes = response.bytes_stream().map(move |chunk| {
            let chunk = chunk.map_err(BoundedHttpClientError::Request)?;
            limiter.observe(&chunk)?;
            Ok::<_, BoundedHttpClientError>(chunk)
        });
        SseStream::from_bytes_stream(bytes).boxed()
    }
}

impl StreamableHttpClient for BoundedHttpClient {
    type Error = BoundedHttpClientError;

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        last_event_id: Option<String>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let mut request = self
            .client
            .get(uri.as_ref())
            .header(ACCEPT, [EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE].join(", "))
            .header(HEADER_SESSION_ID, session_id.as_ref());
        if let Some(last_event_id) = last_event_id {
            request = request.header(HEADER_LAST_EVENT_ID, last_event_id);
        }
        if let Some(auth_token) = auth_token {
            request = request.bearer_auth(auth_token);
        }
        request = self.apply_custom_headers(request, custom_headers)?;
        let response = request.send().await.map_err(client_error)?;
        if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        let response = response.error_for_status().map_err(client_error)?;
        validate_get_stream_content_type(&response)?;
        Ok(self.sse_stream(response))
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let mut request = self
            .client
            .delete(uri.as_ref())
            .header(HEADER_SESSION_ID, session_id.as_ref());
        if let Some(auth_token) = auth_token {
            request = request.bearer_auth(auth_token);
        }
        request = self.apply_custom_headers(request, custom_headers)?;
        let response = request.send().await.map_err(client_error)?;
        if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Ok(());
        }
        response.error_for_status().map_err(client_error)?;
        Ok(())
    }

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let mut request = self
            .client
            .post(uri.as_ref())
            .header(ACCEPT, [EVENT_STREAM_MIME_TYPE, JSON_MIME_TYPE].join(", "));
        if let Some(auth_token) = auth_token {
            request = request.bearer_auth(auth_token);
        }
        request = self.apply_custom_headers(request, custom_headers)?;
        let session_was_attached = session_id.is_some();
        if let Some(session_id) = session_id {
            request = request.header(HEADER_SESSION_ID, session_id.as_ref());
        }
        let response = request.json(&message).send().await.map_err(client_error)?;
        inspect_auth_failure(&response)?;
        let status = response.status();
        if matches!(
            status,
            reqwest::StatusCode::ACCEPTED | reqwest::StatusCode::NO_CONTENT
        ) {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if status == reqwest::StatusCode::NOT_FOUND && session_was_attached {
            return Err(StreamableHttpError::SessionExpired);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).to_string());
        let content_length = response.content_length();
        let response_session_id = response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        if status.is_success()
            && content_length == Some(0)
            && matches!(
                message,
                ClientJsonRpcMessage::Notification(_)
                    | ClientJsonRpcMessage::Response(_)
                    | ClientJsonRpcMessage::Error(_)
            )
        {
            return Ok(StreamableHttpPostResponse::Accepted);
        }
        if !status.is_success() {
            let body = read_bounded(response, self.maximum_message_bytes).await?;
            if content_type
                .as_deref()
                .is_some_and(|value| value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()))
                && let Some(message) = parse_json_rpc_error(&body)
            {
                return Ok(StreamableHttpPostResponse::Json(
                    message,
                    response_session_id,
                ));
            }
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::Owned(
                format!("HTTP {status}"),
            )));
        }
        match content_type.as_deref() {
            Some(value)
                if value
                    .as_bytes()
                    .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes()) =>
            {
                Ok(StreamableHttpPostResponse::Sse(
                    self.sse_stream(response),
                    response_session_id,
                ))
            }
            Some(value) if value.as_bytes().starts_with(JSON_MIME_TYPE.as_bytes()) => {
                let body = read_bounded(response, self.maximum_message_bytes).await?;
                let message = parse_success_json_rpc(&body)?;
                Ok(StreamableHttpPostResponse::Json(
                    message,
                    response_session_id,
                ))
            }
            _ => Err(StreamableHttpError::UnexpectedContentType(content_type)),
        }
    }
}

fn client_error(error: reqwest::Error) -> StreamableHttpError<BoundedHttpClientError> {
    StreamableHttpError::Client(BoundedHttpClientError::Request(error))
}

async fn read_bounded(
    response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, StreamableHttpError<BoundedHttpClientError>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(StreamableHttpError::Client(
            BoundedHttpClientError::ResponseLimitExceeded,
        ));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(maximum_bytes),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(client_error)?;
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(StreamableHttpError::Client(
                BoundedHttpClientError::ResponseLimitExceeded,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_custom_header(name: &HeaderName) -> Result<(), String> {
    let reserved = [
        ACCEPT.as_str(),
        "authorization",
        "connection",
        "content-length",
        "content-type",
        "host",
        HEADER_SESSION_ID,
        HEADER_LAST_EVENT_ID,
        "transfer-encoding",
    ];
    if reserved
        .iter()
        .any(|reserved| name.as_str().eq_ignore_ascii_case(reserved))
    {
        Err(name.to_string())
    } else {
        Ok(())
    }
}

fn validate_get_stream_content_type(
    response: &reqwest::Response,
) -> Result<(), StreamableHttpError<BoundedHttpClientError>> {
    let content_type = response.headers().get(CONTENT_TYPE);
    if content_type.is_some_and(|value| {
        value
            .as_bytes()
            .starts_with(EVENT_STREAM_MIME_TYPE.as_bytes())
    }) {
        Ok(())
    } else {
        Err(StreamableHttpError::UnexpectedContentType(
            content_type.map(|value| String::from_utf8_lossy(value.as_bytes()).to_string()),
        ))
    }
}

fn inspect_auth_failure(
    response: &reqwest::Response,
) -> Result<(), StreamableHttpError<BoundedHttpClientError>> {
    let Some(header) = response.headers().get(WWW_AUTHENTICATE) else {
        return Ok(());
    };
    let header = header.to_str().map_err(|_| {
        StreamableHttpError::UnexpectedServerResponse(Cow::Borrowed(
            "invalid www-authenticate header value",
        ))
    })?;
    match response.status() {
        reqwest::StatusCode::UNAUTHORIZED => Err(StreamableHttpError::AuthRequired(
            AuthRequiredError::new(header.to_string()),
        )),
        reqwest::StatusCode::FORBIDDEN => Err(StreamableHttpError::InsufficientScope(
            InsufficientScopeError::new(header.to_string(), extract_scope(header)),
        )),
        _ => Ok(()),
    }
}

fn extract_scope(header: &str) -> Option<String> {
    let lower = header.to_ascii_lowercase();
    let value = &header[lower.find("scope=")? + "scope=".len()..];
    if let Some(quoted) = value.strip_prefix('"') {
        quoted.find('"').map(|end| quoted[..end].to_string())
    } else {
        let end = value
            .find(|character: char| {
                character == ',' || character == ';' || character.is_whitespace()
            })
            .unwrap_or(value.len());
        (end > 0).then(|| value[..end].to_string())
    }
}

fn parse_json_rpc_error(body: &[u8]) -> Option<ServerJsonRpcMessage> {
    match serde_json::from_slice::<ServerJsonRpcMessage>(body) {
        Ok(message @ JsonRpcMessage::Error(_)) => Some(message),
        _ => None,
    }
}

fn parse_success_json_rpc(
    body: &[u8],
) -> Result<ServerJsonRpcMessage, StreamableHttpError<BoundedHttpClientError>> {
    serde_json::from_slice(body).map_err(|_| {
        StreamableHttpError::UnexpectedServerResponse(Cow::Borrowed(
            "upstream returned malformed JSON-RPC body",
        ))
    })
}

#[derive(Debug)]
struct SseEventLimiter {
    maximum_bytes: usize,
    event_bytes: usize,
    line_has_content: bool,
    previous_was_carriage_return: bool,
}

impl SseEventLimiter {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            event_bytes: 0,
            line_has_content: false,
            previous_was_carriage_return: false,
        }
    }

    fn observe(&mut self, bytes: &[u8]) -> Result<(), BoundedHttpClientError> {
        for byte in bytes {
            self.event_bytes = self.event_bytes.saturating_add(1);
            if self.event_bytes > self.maximum_bytes {
                return Err(BoundedHttpClientError::ResponseLimitExceeded);
            }
            match *byte {
                b'\n' if self.previous_was_carriage_return => {
                    self.previous_was_carriage_return = false;
                }
                b'\n' => self.finish_line(),
                b'\r' => {
                    self.finish_line();
                    self.previous_was_carriage_return = true;
                }
                _ => {
                    self.previous_was_carriage_return = false;
                    self.line_has_content = true;
                }
            }
        }
        Ok(())
    }

    fn finish_line(&mut self) {
        if self.line_has_content {
            self.line_has_content = false;
        } else {
            self.event_bytes = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn response(body: &[u8], content_length: Option<usize>) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let body = body.to_vec();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _read = socket.read(&mut request).await.expect("read request");
            let header = content_length.map_or_else(
                || "Transfer-Encoding: chunked\r\n".to_string(),
                |length| format!("Content-Length: {length}\r\n"),
            );
            socket
                .write_all(
                    format!("HTTP/1.1 200 OK\r\n{header}Connection: close\r\n\r\n").as_bytes(),
                )
                .await
                .expect("write headers");
            if content_length.is_some() {
                socket.write_all(&body).await.expect("write body");
            } else {
                socket
                    .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                    .await
                    .expect("write chunk size");
                socket.write_all(&body).await.expect("write chunk");
                socket
                    .write_all(b"\r\n0\r\n\r\n")
                    .await
                    .expect("finish chunks");
            }
        });
        reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn rejects_declared_body_over_limit_without_reading_it() {
        let response = response(&[b'x'; 128], Some(128)).await;
        assert!(matches!(
            read_bounded(response, 32).await,
            Err(StreamableHttpError::Client(
                BoundedHttpClientError::ResponseLimitExceeded
            ))
        ));
    }

    #[tokio::test]
    async fn rejects_chunked_body_when_accumulated_bytes_cross_limit() {
        let response = response(&[b'x'; 128], None).await;
        assert!(matches!(
            read_bounded(response, 32).await,
            Err(StreamableHttpError::Client(
                BoundedHttpClientError::ResponseLimitExceeded
            ))
        ));
    }

    #[test]
    fn limits_each_sse_event_across_chunk_boundaries() {
        let mut limiter = SseEventLimiter::new(16);
        limiter.observe(b"data: 123").expect("first chunk");
        assert!(matches!(
            limiter.observe(b"456789\n\n"),
            Err(BoundedHttpClientError::ResponseLimitExceeded)
        ));
    }

    #[test]
    fn rejects_malformed_success_json_without_waiting_for_an_sse_response() {
        assert!(matches!(
            parse_success_json_rpc(br#"{"jsonrpc":"2.0","id":1,"result":}"#),
            Err(StreamableHttpError::UnexpectedServerResponse(message))
                if message == "upstream returned malformed JSON-RPC body"
        ));
    }

    #[test]
    fn rejects_headers_that_can_override_transport_security_or_framing() {
        for header in [
            "accept",
            "authorization",
            "connection",
            "content-length",
            "content-type",
            "host",
            "mcp-session-id",
            "last-event-id",
            "transfer-encoding",
        ] {
            assert!(validate_custom_header(&HeaderName::from_static(header)).is_err());
        }
        assert!(validate_custom_header(&HeaderName::from_static("mcp-protocol-version")).is_ok());
        assert!(validate_custom_header(&HeaderName::from_static("x-unpin-test")).is_ok());
    }
}
