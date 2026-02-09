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

#[cfg(all(
    not(feature = "tls-rustls-ring"),
    not(feature = "tls-rustls-aws-lc-rs"),
    not(feature = "tls-native")
))]
compile_error!(
    "reqx requires one TLS backend feature: enable `tls-rustls-ring`, `tls-rustls-aws-lc-rs`, or `tls-native`"
);

pub(crate) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

mod body;
mod client;
mod error;
mod limiters;
mod metrics;
mod proxy;
mod request;
mod response;
mod retry;
mod util;

pub use crate::client::{HttpClient, HttpClientBuilder, TlsBackend};
pub use crate::error::{HttpClientError, HttpClientErrorCode, TimeoutPhase, TransportErrorKind};
pub use crate::metrics::HttpClientMetricsSnapshot;
pub use crate::request::RequestBuilder;
pub use crate::response::{HttpResponse, HttpResponseStream};
pub use crate::retry::{
    PermissiveRetryEligibility, RetryClassifier, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};

pub type ReqxResult<T> = std::result::Result<T, HttpClientError>;

pub mod prelude {
    pub use crate::{
        HttpClient, HttpClientError, HttpClientErrorCode, HttpClientMetricsSnapshot, HttpResponse,
        HttpResponseStream, PermissiveRetryEligibility, ReqxResult, RetryClassifier, RetryDecision,
        RetryEligibility, RetryPolicy, StrictRetryEligibility, TimeoutPhase, TlsBackend,
        TransportErrorKind,
    };
}

#[cfg(test)]
mod tests;
