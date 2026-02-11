use http::{HeaderMap, Method};
use std::time::{Duration, SystemTime};

use crate::util::parse_retry_after;
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
pub enum ErrorCode {
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
    DeserializeJson,
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

impl ErrorCode {
    pub const ALL: [Self; 25] = [
        Self::InvalidUri,
        Self::SerializeJson,
        Self::SerializeQuery,
        Self::SerializeForm,
        Self::RequestBuild,
        Self::Transport,
        Self::Timeout,
        Self::DeadlineExceeded,
        Self::ReadBody,
        Self::ResponseBodyTooLarge,
        Self::HttpStatus,
        Self::DeserializeJson,
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

    pub const fn all() -> &'static [Self] {
        &Self::ALL
    }

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
            Self::DeserializeJson => "deserialize_json",
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
pub enum Error {
    #[error("invalid request uri: {uri}")]
    InvalidUri { uri: String },
    #[error("failed to serialize request json: {source}")]
    SerializeJson {
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
    #[error("http status error {status} for {method} {uri}")]
    HttpStatus {
        status: u16,
        method: Method,
        uri: String,
        headers: Box<HeaderMap>,
        body: String,
    },
    #[error("failed to decode response json: {source}")]
    DeserializeJson {
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
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidUri { .. } => ErrorCode::InvalidUri,
            Self::SerializeJson { .. } => ErrorCode::SerializeJson,
            Self::SerializeQuery { .. } => ErrorCode::SerializeQuery,
            Self::SerializeForm { .. } => ErrorCode::SerializeForm,
            Self::RequestBuild { .. } => ErrorCode::RequestBuild,
            Self::Transport { .. } => ErrorCode::Transport,
            Self::Timeout { .. } => ErrorCode::Timeout,
            Self::DeadlineExceeded { .. } => ErrorCode::DeadlineExceeded,
            Self::ReadBody { .. } => ErrorCode::ReadBody,
            Self::ResponseBodyTooLarge { .. } => ErrorCode::ResponseBodyTooLarge,
            Self::HttpStatus { .. } => ErrorCode::HttpStatus,
            Self::DeserializeJson { .. } => ErrorCode::DeserializeJson,
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

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub const fn response_headers(&self) -> Option<&HeaderMap> {
        match self {
            Self::HttpStatus { headers, .. } => Some(headers),
            _ => None,
        }
    }

    pub fn retry_after(&self, now: SystemTime) -> Option<Duration> {
        let headers = self.response_headers()?;
        parse_retry_after(headers, now)
    }

    pub fn request_id(&self) -> Option<&str> {
        let headers = self.response_headers()?;
        headers
            .get("x-request-id")
            .or_else(|| headers.get("x-amz-request-id"))
            .or_else(|| headers.get("x-amz-id-2"))
            .and_then(|value| value.to_str().ok())
    }
}
