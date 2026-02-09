use http::Method;
use thiserror::Error;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportErrorKind {
    Dns,
    Connect,
    Tls,
    Read,
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
pub enum TimeoutPhase {
    Transport,
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
pub enum HttpClientErrorCode {
    InvalidUri,
    SerializeJson,
    SerializeQuery,
    SerializeForm,
    RequestBuild,
    Transport,
    Timeout,
    DeadlineExceeded,
    ReadBody,
    ResponseBodyTooLarge,
    HttpStatus,
    Deserialize,
    InvalidHeaderName,
    InvalidHeaderValue,
    DecodeContentEncoding,
    ConcurrencyLimitClosed,
    TlsBackendUnavailable,
    TlsBackendInit,
    TlsConfig,
    RetryBudgetExhausted,
    CircuitOpen,
    MissingRedirectLocation,
    InvalidRedirectLocation,
    RedirectLimitExceeded,
    RedirectBodyNotReplayable,
}

impl HttpClientErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUri => "invalid_uri",
            Self::SerializeJson => "serialize_json",
            Self::SerializeQuery => "serialize_query",
            Self::SerializeForm => "serialize_form",
            Self::RequestBuild => "request_build",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::ReadBody => "read_body",
            Self::ResponseBodyTooLarge => "response_body_too_large",
            Self::HttpStatus => "http_status",
            Self::Deserialize => "deserialize",
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

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpClientError {
    #[error("invalid request uri: {uri}")]
    InvalidUri { uri: String },
    #[error("failed to serialize request json: {source}")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize request query: {source}")]
    SerializeQuery {
        #[source]
        source: serde_urlencoded::ser::Error,
    },
    #[error("failed to serialize request form: {source}")]
    SerializeForm {
        #[source]
        source: serde_urlencoded::ser::Error,
    },
    #[error("failed to build http request: {source}")]
    RequestBuild {
        #[source]
        source: http::Error,
    },
    #[error("http transport error ({kind}) for {method} {uri}: {source}")]
    Transport {
        kind: TransportErrorKind,
        method: Method,
        uri: String,
        #[source]
        source: BoxError,
    },
    #[error("http request timed out in {phase} after {timeout_ms}ms for {method} {uri}")]
    Timeout {
        phase: TimeoutPhase,
        timeout_ms: u128,
        method: Method,
        uri: String,
    },
    #[error("http request deadline exceeded after {timeout_ms}ms for {method} {uri}")]
    DeadlineExceeded {
        timeout_ms: u128,
        method: Method,
        uri: String,
    },
    #[error("failed to read response body: {source}")]
    ReadBody {
        #[source]
        source: BoxError,
    },
    #[error(
        "response body too large ({actual_bytes} bytes > {limit_bytes} bytes) for {method} {uri}"
    )]
    ResponseBodyTooLarge {
        limit_bytes: usize,
        actual_bytes: usize,
        method: Method,
        uri: String,
    },
    #[error("http status error {status} for {method} {uri}: {body}")]
    HttpStatus {
        status: u16,
        method: Method,
        uri: String,
        body: String,
    },
    #[error("failed to decode response json: {source}; body={body}")]
    Deserialize {
        #[source]
        source: serde_json::Error,
        body: String,
    },
    #[error("invalid header name {name}: {source}")]
    InvalidHeaderName {
        name: String,
        #[source]
        source: http::header::InvalidHeaderName,
    },
    #[error("invalid header value for {name}: {source}")]
    InvalidHeaderValue {
        name: String,
        #[source]
        source: http::header::InvalidHeaderValue,
    },
    #[error("failed to decode response content-encoding {encoding} for {method} {uri}: {message}")]
    DecodeContentEncoding {
        encoding: String,
        method: Method,
        uri: String,
        message: String,
    },
    #[error("request concurrency limiter is closed")]
    ConcurrencyLimitClosed,
    #[error("requested tls backend is not enabled in this build: {backend}")]
    TlsBackendUnavailable { backend: &'static str },
    #[error("failed to initialize tls backend {backend}: {message}")]
    TlsBackendInit {
        backend: &'static str,
        message: String,
    },
    #[error("invalid tls configuration for backend {backend}: {message}")]
    TlsConfig {
        backend: &'static str,
        message: String,
    },
    #[error("retry budget exhausted for {method} {uri}")]
    RetryBudgetExhausted { method: Method, uri: String },
    #[error("circuit breaker is open for {method} {uri}; retry after {retry_after_ms}ms")]
    CircuitOpen {
        method: Method,
        uri: String,
        retry_after_ms: u128,
    },
    #[error("redirect response {status} missing location header for {method} {uri}")]
    MissingRedirectLocation {
        status: u16,
        method: Method,
        uri: String,
    },
    #[error("invalid redirect location {location} for {method} {uri}")]
    InvalidRedirectLocation {
        location: String,
        method: Method,
        uri: String,
    },
    #[error("redirect limit exceeded ({max_redirects}) for {method} {uri}")]
    RedirectLimitExceeded {
        max_redirects: usize,
        method: Method,
        uri: String,
    },
    #[error("cannot follow redirect for non-replayable request body: {method} {uri}")]
    RedirectBodyNotReplayable { method: Method, uri: String },
}

impl HttpClientError {
    pub const fn code(&self) -> HttpClientErrorCode {
        match self {
            Self::InvalidUri { .. } => HttpClientErrorCode::InvalidUri,
            Self::Serialize { .. } => HttpClientErrorCode::SerializeJson,
            Self::SerializeQuery { .. } => HttpClientErrorCode::SerializeQuery,
            Self::SerializeForm { .. } => HttpClientErrorCode::SerializeForm,
            Self::RequestBuild { .. } => HttpClientErrorCode::RequestBuild,
            Self::Transport { .. } => HttpClientErrorCode::Transport,
            Self::Timeout { .. } => HttpClientErrorCode::Timeout,
            Self::DeadlineExceeded { .. } => HttpClientErrorCode::DeadlineExceeded,
            Self::ReadBody { .. } => HttpClientErrorCode::ReadBody,
            Self::ResponseBodyTooLarge { .. } => HttpClientErrorCode::ResponseBodyTooLarge,
            Self::HttpStatus { .. } => HttpClientErrorCode::HttpStatus,
            Self::Deserialize { .. } => HttpClientErrorCode::Deserialize,
            Self::InvalidHeaderName { .. } => HttpClientErrorCode::InvalidHeaderName,
            Self::InvalidHeaderValue { .. } => HttpClientErrorCode::InvalidHeaderValue,
            Self::DecodeContentEncoding { .. } => HttpClientErrorCode::DecodeContentEncoding,
            Self::ConcurrencyLimitClosed => HttpClientErrorCode::ConcurrencyLimitClosed,
            Self::TlsBackendUnavailable { .. } => HttpClientErrorCode::TlsBackendUnavailable,
            Self::TlsBackendInit { .. } => HttpClientErrorCode::TlsBackendInit,
            Self::TlsConfig { .. } => HttpClientErrorCode::TlsConfig,
            Self::RetryBudgetExhausted { .. } => HttpClientErrorCode::RetryBudgetExhausted,
            Self::CircuitOpen { .. } => HttpClientErrorCode::CircuitOpen,
            Self::MissingRedirectLocation { .. } => HttpClientErrorCode::MissingRedirectLocation,
            Self::InvalidRedirectLocation { .. } => HttpClientErrorCode::InvalidRedirectLocation,
            Self::RedirectLimitExceeded { .. } => HttpClientErrorCode::RedirectLimitExceeded,
            Self::RedirectBodyNotReplayable { .. } => {
                HttpClientErrorCode::RedirectBodyNotReplayable
            }
        }
    }
}
