use http::{HeaderMap, Method};
use std::time::{Duration, SystemTime};

use crate::util::parse_retry_after;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn summarize_error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut messages = Vec::new();
    let mut current = Some(error);

    while let Some(source) = current {
        let message = source.to_string();
        if messages.last() != Some(&message) {
            messages.push(message);
        }
        current = source.source();
    }

    messages.join(": ")
}

pub(crate) fn transport_error(
    kind: TransportErrorKind,
    method: Method,
    uri: String,
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    let source: BoxError = Box::new(source);
    let message = summarize_error_chain(source.as_ref());
    Error::Transport {
        kind,
        method,
        uri,
        message,
        source,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
/// High-level transport failure category.
pub enum TransportErrorKind {
    /// DNS lookup or name resolution failed.
    Dns,
    /// Opening the TCP or proxy connection failed.
    Connect,
    /// TLS negotiation or certificate validation failed.
    Tls,
    /// A connected transport failed while reading the response.
    Read,
    /// Another transport failure that did not fit a more specific category.
    Other,
}

impl std::fmt::Display for TransportErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Dns => "dns",
            Self::Connect => "connect",
            Self::Tls => "tls",
            Self::Read => "read",
            Self::Other => "other",
        };
        formatter.write_str(text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
/// Request phase associated with a timeout.
pub enum TimeoutPhase {
    /// The timeout happened before the response body stream was handed out.
    Transport,
    /// The timeout happened while reading the response body stream.
    ResponseBody,
}

impl std::fmt::Display for TimeoutPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Transport => "transport",
            Self::ResponseBody => "response_body",
        };
        formatter.write_str(text)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
/// Stable machine-readable error code.
pub enum ErrorCode {
    /// The base URL or request URI was invalid.
    InvalidUri,
    /// A `no_proxy` rule could not be parsed.
    InvalidNoProxyRule,
    /// Proxy configuration was internally inconsistent.
    InvalidProxyConfig,
    /// Adaptive concurrency settings were invalid.
    InvalidAdaptiveConcurrencyPolicy,
    /// Serializing a JSON request body failed.
    SerializeJson,
    /// Serializing query parameters failed.
    SerializeQuery,
    /// Serializing a form request body failed.
    SerializeForm,
    /// Building the HTTP request object failed.
    RequestBuild,
    /// The transport layer failed before a response was received.
    Transport,
    /// An operation hit a phase timeout.
    Timeout,
    /// The overall request deadline elapsed.
    DeadlineExceeded,
    /// Reading a buffered response body failed.
    ReadBody,
    /// Writing a streamed response body to a sink failed.
    WriteBody,
    /// The response body exceeded the configured byte limit.
    ResponseBodyTooLarge,
    /// The response status failed the active status policy.
    HttpStatus,
    /// Deserializing a JSON response body failed.
    DeserializeJson,
    /// Decoding the response body as UTF-8 failed.
    DecodeText,
    /// A header name was invalid.
    InvalidHeaderName,
    /// A header value was invalid.
    InvalidHeaderValue,
    /// Decoding a compressed response body failed.
    DecodeContentEncoding,
    /// A request could not enter a closed concurrency limiter.
    ConcurrencyLimitClosed,
    /// The selected TLS backend is not compiled into this build.
    TlsBackendUnavailable,
    /// Initializing the selected TLS backend failed.
    TlsBackendInit,
    /// TLS configuration was not supported by the selected backend.
    TlsConfig,
    /// Retry budget enforcement rejected another retry attempt.
    RetryBudgetExhausted,
    /// The circuit breaker rejected the request.
    CircuitOpen,
    /// A redirect response did not contain a `Location` header.
    MissingRedirectLocation,
    /// A redirect target could not be parsed.
    InvalidRedirectLocation,
    /// Redirect handling exceeded the configured redirect limit.
    RedirectLimitExceeded,
    /// Redirect handling required replaying a non-replayable request body.
    RedirectBodyNotReplayable,
}

impl ErrorCode {
    const ALL: &'static [Self] = &[
        Self::InvalidUri,
        Self::InvalidNoProxyRule,
        Self::InvalidProxyConfig,
        Self::InvalidAdaptiveConcurrencyPolicy,
        Self::SerializeJson,
        Self::SerializeQuery,
        Self::SerializeForm,
        Self::RequestBuild,
        Self::Transport,
        Self::Timeout,
        Self::DeadlineExceeded,
        Self::ReadBody,
        Self::WriteBody,
        Self::ResponseBodyTooLarge,
        Self::HttpStatus,
        Self::DeserializeJson,
        Self::DecodeText,
        Self::InvalidHeaderName,
        Self::InvalidHeaderValue,
        Self::DecodeContentEncoding,
        Self::ConcurrencyLimitClosed,
        Self::TlsBackendUnavailable,
        Self::TlsBackendInit,
        Self::TlsConfig,
        Self::RetryBudgetExhausted,
        Self::CircuitOpen,
        Self::MissingRedirectLocation,
        Self::InvalidRedirectLocation,
        Self::RedirectLimitExceeded,
        Self::RedirectBodyNotReplayable,
    ];

    /// Returns a slice of all currently defined error codes.
    pub const fn all() -> &'static [Self] {
        Self::ALL
    }

    /// Returns the stable string form of this error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUri => "invalid_uri",
            Self::InvalidNoProxyRule => "invalid_no_proxy_rule",
            Self::InvalidProxyConfig => "invalid_proxy_config",
            Self::InvalidAdaptiveConcurrencyPolicy => "invalid_adaptive_concurrency_policy",
            Self::SerializeJson => "serialize_json",
            Self::SerializeQuery => "serialize_query",
            Self::SerializeForm => "serialize_form",
            Self::RequestBuild => "request_build",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ReadBody => "read_body",
            Self::WriteBody => "write_body",
            Self::ResponseBodyTooLarge => "response_body_too_large",
            Self::HttpStatus => "http_status",
            Self::DeserializeJson => "deserialize_json",
            Self::DecodeText => "decode_text",
            Self::InvalidHeaderName => "invalid_header_name",
            Self::InvalidHeaderValue => "invalid_header_value",
            Self::DecodeContentEncoding => "decode_content_encoding",
            Self::ConcurrencyLimitClosed => "concurrency_limit_closed",
            Self::TlsBackendUnavailable => "tls_backend_unavailable",
            Self::TlsBackendInit => "tls_backend_init",
            Self::TlsConfig => "tls_config",
            Self::RetryBudgetExhausted => "retry_budget_exhausted",
            Self::CircuitOpen => "circuit_open",
            Self::MissingRedirectLocation => "missing_redirect_location",
            Self::InvalidRedirectLocation => "invalid_redirect_location",
            Self::RedirectLimitExceeded => "redirect_limit_exceeded",
            Self::RedirectBodyNotReplayable => "redirect_body_not_replayable",
        }
    }
}

#[derive(thiserror::Error)]
#[non_exhaustive]
/// Error returned by `reqx`.
pub enum Error {
    /// The base URL or request URI was invalid.
    #[error("invalid request uri: {uri}")]
    InvalidUri {
        /// Invalid URI string.
        uri: String,
    },
    /// A `no_proxy` rule could not be parsed.
    #[error("invalid no_proxy rule: {rule:?}")]
    InvalidNoProxyRule {
        /// Original invalid rule string.
        rule: String,
    },
    /// Proxy configuration was internally inconsistent.
    #[error("invalid proxy configuration for {proxy_uri}: {message}")]
    InvalidProxyConfig {
        /// Redacted proxy URI.
        proxy_uri: String,
        /// Human-readable validation message.
        message: String,
    },
    /// `proxy_authorization(...)` was used without configuring `http_proxy(...)`.
    #[error("proxy_authorization requires http_proxy to be configured")]
    ProxyAuthorizationRequiresHttpProxy,
    /// Adaptive concurrency settings were invalid.
    #[error(
        "invalid adaptive concurrency policy (min={min_limit}, initial={initial_limit}, max={max_limit}): {message}"
    )]
    InvalidAdaptiveConcurrencyPolicy {
        /// Configured minimum limit.
        min_limit: usize,
        /// Configured initial limit.
        initial_limit: usize,
        /// Configured maximum limit.
        max_limit: usize,
        /// Validation failure explanation.
        message: &'static str,
    },
    /// Serializing a JSON request body failed.
    #[error("failed to serialize request json: {source}")]
    SerializeJson {
        #[source]
        /// Source serialization error.
        source: serde_json::Error,
    },
    /// Serializing query parameters failed.
    #[error("failed to serialize request query: {source}")]
    SerializeQuery {
        #[source]
        /// Source serialization error.
        source: serde_urlencoded::ser::Error,
    },
    /// Serializing a form request body failed.
    #[error("failed to serialize request form: {source}")]
    SerializeForm {
        #[source]
        /// Source serialization error.
        source: serde_urlencoded::ser::Error,
    },
    /// Building the HTTP request object failed.
    #[error("failed to build http request: {source}")]
    RequestBuild {
        #[source]
        /// Source request construction error.
        source: http::Error,
    },
    /// The transport layer failed before a response was received.
    #[error("http transport error ({kind}) for {method} {uri}: {message}")]
    Transport {
        /// High-level transport failure category.
        kind: TransportErrorKind,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
        /// Flattened summary of the underlying error chain.
        message: String,
        #[source]
        /// Underlying transport error.
        source: BoxError,
    },
    /// A request phase exceeded its timeout.
    #[error("http request timed out in {phase} after {timeout_ms}ms for {method} {uri}")]
    Timeout {
        /// Timeout phase that elapsed.
        phase: TimeoutPhase,
        /// Timeout duration in milliseconds.
        timeout_ms: u128,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// The overall request deadline elapsed.
    #[error("http request deadline exceeded after {timeout_ms}ms for {method} {uri}")]
    DeadlineExceeded {
        /// Deadline duration in milliseconds.
        timeout_ms: u128,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// Reading a buffered response body failed.
    #[error("failed to read response body: {source}")]
    ReadBody {
        #[source]
        /// Underlying body read error.
        source: BoxError,
    },
    /// Writing a streamed response body to a sink failed.
    #[error("failed to write response body for {method} {uri}: {source}")]
    WriteBody {
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
        #[source]
        /// Underlying writer error.
        source: BoxError,
    },
    /// The response body exceeded the configured byte limit.
    #[error(
        "response body too large ({actual_bytes} bytes > {limit_bytes} bytes) for {method} {uri}"
    )]
    ResponseBodyTooLarge {
        /// Configured body size limit in bytes.
        limit_bytes: usize,
        /// Actual body size observed in bytes.
        actual_bytes: usize,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// The response status failed the active status policy.
    #[error("http status error {status} for {method} {uri}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
        /// Captured response headers.
        headers: Box<HeaderMap>,
        /// Truncated response body text.
        body: String,
    },
    /// Deserializing a JSON response body failed.
    #[error("failed to decode response json: {source}")]
    DeserializeJson {
        #[source]
        /// Source deserialization error.
        source: serde_json::Error,
        /// Truncated response body text.
        body: String,
    },
    /// Decoding the response body as UTF-8 failed.
    #[error("failed to decode response text as utf-8: {source}")]
    DecodeText {
        #[source]
        /// Source UTF-8 decoding error.
        source: std::str::Utf8Error,
        /// Truncated response body text.
        body: String,
    },
    /// A header name was invalid.
    #[error("invalid header name {name}: {source}")]
    InvalidHeaderName {
        /// Header name that failed validation.
        name: String,
        #[source]
        /// Source header parsing error.
        source: http::header::InvalidHeaderName,
    },
    /// A header value was invalid.
    #[error("invalid header value for {name}: {source}")]
    InvalidHeaderValue {
        /// Header name associated with the invalid value.
        name: String,
        #[source]
        /// Source header parsing error.
        source: http::header::InvalidHeaderValue,
    },
    /// Decoding a compressed response body failed.
    #[error("failed to decode response content-encoding {encoding} for {method} {uri}: {message}")]
    DecodeContentEncoding {
        /// Content encoding that failed to decode.
        encoding: String,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
        /// Human-readable decode failure message.
        message: String,
    },
    /// A request could not enter a closed concurrency limiter.
    #[error("request concurrency limiter is closed")]
    ConcurrencyLimitClosed,
    /// The selected TLS backend is not compiled into this build.
    #[error("requested tls backend is not enabled in this build: {backend}")]
    TlsBackendUnavailable {
        /// Name of the unavailable backend.
        backend: &'static str,
    },
    /// Initializing the selected TLS backend failed.
    #[error("failed to initialize tls backend {backend}: {message}")]
    TlsBackendInit {
        /// Name of the backend that failed to initialize.
        backend: &'static str,
        /// Human-readable initialization failure message.
        message: String,
    },
    /// TLS configuration was not supported by the selected backend.
    #[error("invalid tls configuration for backend {backend}: {message}")]
    TlsConfig {
        /// Name of the backend that rejected the configuration.
        backend: &'static str,
        /// Human-readable validation failure message.
        message: String,
    },
    /// Retry budget enforcement rejected another retry attempt.
    #[error("retry budget exhausted for {method} {uri}")]
    RetryBudgetExhausted {
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// The circuit breaker rejected the request.
    #[error("circuit breaker is open for {method} {uri}; retry after {retry_after_ms}ms")]
    CircuitOpen {
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
        /// Retry-after delay in milliseconds.
        retry_after_ms: u128,
    },
    /// A redirect response did not include a `Location` header.
    #[error("redirect response {status} missing location header for {method} {uri}")]
    MissingRedirectLocation {
        /// Redirect status code.
        status: u16,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// A redirect target could not be parsed.
    #[error("invalid redirect location {location} for {method} {uri}")]
    InvalidRedirectLocation {
        /// Unparseable redirect target.
        location: String,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// Redirect handling exceeded the configured redirect limit.
    #[error("redirect limit exceeded ({max_redirects}) for {method} {uri}")]
    RedirectLimitExceeded {
        /// Maximum redirects permitted.
        max_redirects: usize,
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
    /// Redirect handling required replaying a non-replayable request body.
    #[error("cannot follow redirect for non-replayable request body: {method} {uri}")]
    RedirectBodyNotReplayable {
        /// Request method.
        method: Method,
        /// Redacted request URI.
        uri: String,
    },
}

impl std::fmt::Debug for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Error")
            .field("code", &self.code())
            .field("message", &self.to_string())
            .finish()
    }
}

impl Error {
    /// Returns the stable machine-readable error code for this error.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidUri { .. } => ErrorCode::InvalidUri,
            Self::InvalidNoProxyRule { .. } => ErrorCode::InvalidNoProxyRule,
            Self::InvalidProxyConfig { .. } | Self::ProxyAuthorizationRequiresHttpProxy => {
                ErrorCode::InvalidProxyConfig
            }
            Self::InvalidAdaptiveConcurrencyPolicy { .. } => {
                ErrorCode::InvalidAdaptiveConcurrencyPolicy
            }
            Self::SerializeJson { .. } => ErrorCode::SerializeJson,
            Self::SerializeQuery { .. } => ErrorCode::SerializeQuery,
            Self::SerializeForm { .. } => ErrorCode::SerializeForm,
            Self::RequestBuild { .. } => ErrorCode::RequestBuild,
            Self::Transport { .. } => ErrorCode::Transport,
            Self::Timeout { .. } => ErrorCode::Timeout,
            Self::DeadlineExceeded { .. } => ErrorCode::DeadlineExceeded,
            Self::ReadBody { .. } => ErrorCode::ReadBody,
            Self::WriteBody { .. } => ErrorCode::WriteBody,
            Self::ResponseBodyTooLarge { .. } => ErrorCode::ResponseBodyTooLarge,
            Self::HttpStatus { .. } => ErrorCode::HttpStatus,
            Self::DeserializeJson { .. } => ErrorCode::DeserializeJson,
            Self::DecodeText { .. } => ErrorCode::DecodeText,
            Self::InvalidHeaderName { .. } => ErrorCode::InvalidHeaderName,
            Self::InvalidHeaderValue { .. } => ErrorCode::InvalidHeaderValue,
            Self::DecodeContentEncoding { .. } => ErrorCode::DecodeContentEncoding,
            Self::ConcurrencyLimitClosed => ErrorCode::ConcurrencyLimitClosed,
            Self::TlsBackendUnavailable { .. } => ErrorCode::TlsBackendUnavailable,
            Self::TlsBackendInit { .. } => ErrorCode::TlsBackendInit,
            Self::TlsConfig { .. } => ErrorCode::TlsConfig,
            Self::RetryBudgetExhausted { .. } => ErrorCode::RetryBudgetExhausted,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::MissingRedirectLocation { .. } => ErrorCode::MissingRedirectLocation,
            Self::InvalidRedirectLocation { .. } => ErrorCode::InvalidRedirectLocation,
            Self::RedirectLimitExceeded { .. } => ErrorCode::RedirectLimitExceeded,
            Self::RedirectBodyNotReplayable { .. } => ErrorCode::RedirectBodyNotReplayable,
        }
    }

    /// Returns the HTTP status code for [`Error::HttpStatus`].
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns the captured response headers for [`Error::HttpStatus`].
    pub const fn response_headers(&self) -> Option<&HeaderMap> {
        match self {
            Self::HttpStatus { headers, .. } => Some(headers),
            _ => None,
        }
    }

    /// Parses a `Retry-After` hint from the captured response headers.
    pub fn retry_after(&self, now: SystemTime) -> Option<Duration> {
        let headers = self.response_headers()?;
        parse_retry_after(headers, now)
    }

    /// Returns a request identifier from captured response headers when available.
    pub fn request_id(&self) -> Option<&str> {
        let headers = self.response_headers()?;
        headers
            .get("x-request-id")
            .or_else(|| headers.get("x-amz-request-id"))
            .or_else(|| headers.get("x-amz-id-2"))
            .and_then(|value| value.to_str().ok())
    }

    /// Returns the originating request method when the error carries one.
    pub fn request_method(&self) -> Option<&Method> {
        match self {
            Self::Transport { method, .. }
            | Self::Timeout { method, .. }
            | Self::DeadlineExceeded { method, .. }
            | Self::WriteBody { method, .. }
            | Self::ResponseBodyTooLarge { method, .. }
            | Self::HttpStatus { method, .. }
            | Self::DecodeContentEncoding { method, .. }
            | Self::RetryBudgetExhausted { method, .. }
            | Self::CircuitOpen { method, .. }
            | Self::MissingRedirectLocation { method, .. }
            | Self::InvalidRedirectLocation { method, .. }
            | Self::RedirectLimitExceeded { method, .. }
            | Self::RedirectBodyNotReplayable { method, .. } => Some(method),
            _ => None,
        }
    }

    /// Returns the redacted request URI associated with this error.
    pub fn request_uri_redacted(&self) -> Option<&str> {
        match self {
            Self::InvalidUri { uri }
            | Self::InvalidProxyConfig { proxy_uri: uri, .. }
            | Self::Transport { uri, .. }
            | Self::Timeout { uri, .. }
            | Self::DeadlineExceeded { uri, .. }
            | Self::WriteBody { uri, .. }
            | Self::ResponseBodyTooLarge { uri, .. }
            | Self::HttpStatus { uri, .. }
            | Self::DecodeContentEncoding { uri, .. }
            | Self::RetryBudgetExhausted { uri, .. }
            | Self::CircuitOpen { uri, .. }
            | Self::MissingRedirectLocation { uri, .. }
            | Self::InvalidRedirectLocation { uri, .. }
            | Self::RedirectLimitExceeded { uri, .. }
            | Self::RedirectBodyNotReplayable { uri, .. } => Some(uri),
            _ => None,
        }
    }

    /// Returns an owned copy of the redacted request URI.
    pub fn request_uri_redacted_owned(&self) -> Option<String> {
        self.request_uri_redacted().map(ToOwned::to_owned)
    }

    /// Returns just the request path component when a request URI is available.
    pub fn request_path(&self) -> Option<String> {
        let uri = self.request_uri_redacted()?;
        if let Ok(parsed) = uri.parse::<http::Uri>() {
            let path = parsed.path();
            if !path.is_empty() {
                return Some(path.to_owned());
            }
        }
        let without_query = uri.split_once('?').map_or(uri, |(left, _)| left);
        let without_fragment = without_query
            .split_once('#')
            .map_or(without_query, |(left, _)| left);
        if without_fragment.is_empty() {
            None
        } else {
            Some(without_fragment.to_owned())
        }
    }
}
