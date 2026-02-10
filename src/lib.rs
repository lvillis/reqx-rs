#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

//! `reqx` is an internal HTTP transport crate for API SDKs with HTTP/1.1 + HTTP/2 support.
//!
//! # Quick Start
//!
//! ```no_run
//! use std::time::Duration;
//! use reqx::prelude::{HttpClient, RetryPolicy};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! struct CreateItemResponse {
//!     id: String,
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = HttpClient::builder("https://api.example.com")
//!         .client_name("my-sdk")
//!         .request_timeout(Duration::from_secs(3))
//!         .total_timeout(Duration::from_secs(8))
//!         .retry_policy(
//!             RetryPolicy::standard()
//!                 .max_attempts(3)
//!                 .base_backoff(Duration::from_millis(100))
//!                 .max_backoff(Duration::from_millis(800)),
//!         )
//!         .try_build()?;
//!
//!     let created: CreateItemResponse = client
//!         .post("/v1/items")
//!         .idempotency_key("create-item-001")?
//!         .json(&serde_json::json!({ "name": "demo" }))?
//!         .send_json()
//!         .await?;
//!
//!     println!("created id={}", created.id);
//!     Ok(())
//! }
//! ```
//!
//! # Recommended Defaults
//!
//! - Use `RetryPolicy::standard()` for SDK traffic.
//! - Set both request timeout and total timeout.
//! - For `POST` retries, always set `idempotency_key(...)`.

#[cfg(not(any(feature = "_async", feature = "_blocking")))]
compile_error!(
    "reqx requires at least one transport feature: enable an `async-tls-*` or `blocking-tls-*` feature"
);

#[cfg(all(
    feature = "_async",
    not(feature = "async-tls-rustls-ring"),
    not(feature = "async-tls-rustls-aws-lc-rs"),
    not(feature = "async-tls-native")
))]
compile_error!(
    "async transport requires one async TLS backend: enable `async-tls-rustls-ring`, `async-tls-rustls-aws-lc-rs`, or `async-tls-native`"
);

#[cfg(all(
    feature = "_blocking",
    not(feature = "blocking-tls-rustls-ring"),
    not(feature = "blocking-tls-rustls-aws-lc-rs"),
    not(feature = "blocking-tls-native")
))]
compile_error!(
    "blocking transport requires one blocking TLS backend: enable `blocking-tls-rustls-ring`, `blocking-tls-rustls-aws-lc-rs`, or `blocking-tls-native`"
);

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

#[cfg(feature = "_async")]
mod async_client;
#[cfg(feature = "_blocking")]
mod blocking_client;
mod core;
mod http;
mod rate_limit;
mod resilience;
mod tls;

#[cfg(feature = "_async")]
pub(crate) use crate::async_client::body;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::client;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::limiters;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::request;
pub(crate) use crate::core::error;
pub(crate) use crate::core::metrics;
pub(crate) use crate::core::policy;
pub(crate) use crate::core::proxy;
pub(crate) use crate::core::retry;
pub(crate) use crate::core::util;
pub(crate) use crate::http::response;

#[cfg(feature = "_blocking")]
pub use crate::blocking_client::{
    HttpClient as BlockingHttpClient, HttpClientBuilder as BlockingHttpClientBuilder,
    RequestBuilder as BlockingRequestBuilder,
};
#[cfg(feature = "_async")]
pub use crate::client::{HttpClient, HttpClientBuilder};
pub use crate::error::{HttpClientError, HttpClientErrorCode, TimeoutPhase, TransportErrorKind};
pub use crate::metrics::HttpClientMetricsSnapshot;
pub use crate::policy::{HttpInterceptor, RedirectPolicy, RequestContext};
pub use crate::rate_limit::RateLimitPolicy;
#[cfg(feature = "_async")]
pub use crate::request::RequestBuilder;
pub use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy};
#[cfg(feature = "_blocking")]
pub use crate::response::BlockingHttpResponseStream;
pub use crate::response::HttpResponse;
#[cfg(feature = "_async")]
pub use crate::response::HttpResponseStream;
pub use crate::retry::{
    PermissiveRetryEligibility, RetryClassifier, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
pub use crate::tls::TlsBackend;

#[cfg(feature = "_blocking")]
pub mod blocking {
    pub use crate::blocking_client::{HttpClient, HttpClientBuilder, RequestBuilder};
}

pub type ReqxResult<T> = std::result::Result<T, HttpClientError>;

pub mod prelude {
    pub use crate::{
        AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, HttpClientError, HttpClientErrorCode,
        HttpClientMetricsSnapshot, HttpInterceptor, HttpResponse, PermissiveRetryEligibility,
        RateLimitPolicy, RedirectPolicy, RequestContext, ReqxResult, RetryBudgetPolicy,
        RetryClassifier, RetryDecision, RetryEligibility, RetryPolicy, StrictRetryEligibility,
        TimeoutPhase, TlsBackend, TransportErrorKind,
    };
    #[cfg(feature = "_blocking")]
    pub use crate::{
        BlockingHttpClient, BlockingHttpClientBuilder, BlockingHttpResponseStream,
        BlockingRequestBuilder, blocking,
    };
    #[cfg(feature = "_async")]
    pub use crate::{HttpClient, HttpResponseStream};
}

#[cfg(all(test, feature = "_async"))]
mod tests;
