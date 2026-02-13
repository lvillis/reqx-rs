#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    not(any(feature = "_async", feature = "_blocking")),
    allow(dead_code, unused_imports)
)]

//! `reqx` is an internal HTTP transport crate for API SDKs with HTTP/1.1 + HTTP/2 support.
//!
//! # Quick Start
//!
//! ```no_run
//! # #[cfg(feature = "_async")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//! use reqx::prelude::{Client, RetryPolicy};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! struct CreateItemResponse {
//!     id: String,
//! }
//!
//!     let client = Client::builder("https://api.example.com")
//!         .client_name("my-sdk")
//!         .request_timeout(Duration::from_secs(3))
//!         .total_timeout(Duration::from_secs(8))
//!         .retry_policy(
//!             RetryPolicy::standard()
//!                 .max_attempts(3)
//!                 .base_backoff(Duration::from_millis(100))
//!                 .max_backoff(Duration::from_millis(800)),
//!         )
//!         .build()?;
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
//! # }
//! ```
//!
//! # Recommended Defaults
//!
//! - Use `RetryPolicy::standard()` for SDK traffic.
//! - Set both request timeout and total timeout.
//! - For `POST` retries, always set `idempotency_key(...)`.

#[cfg(all(
    feature = "strict-feature-guards",
    not(any(feature = "_async", feature = "_blocking"))
))]
compile_error!(
    "reqx requires at least one transport feature: enable an `async-tls-*` or `blocking-tls-*` feature"
);

#[cfg(all(
    feature = "strict-feature-guards",
    feature = "_async",
    not(feature = "async-tls-rustls-ring"),
    not(feature = "async-tls-rustls-aws-lc-rs"),
    not(feature = "async-tls-native")
))]
compile_error!(
    "async transport requires one async TLS backend: enable `async-tls-rustls-ring`, `async-tls-rustls-aws-lc-rs`, or `async-tls-native`"
);

#[cfg(all(
    feature = "strict-feature-guards",
    feature = "_async",
    any(
        all(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs"
        ),
        all(feature = "async-tls-rustls-ring", feature = "async-tls-native"),
        all(feature = "async-tls-rustls-aws-lc-rs", feature = "async-tls-native")
    )
))]
compile_error!(
    "async transport requires exactly one TLS backend: choose only one of `async-tls-rustls-ring`, `async-tls-rustls-aws-lc-rs`, or `async-tls-native`"
);

#[cfg(all(
    feature = "strict-feature-guards",
    feature = "_blocking",
    not(feature = "blocking-tls-rustls-ring"),
    not(feature = "blocking-tls-rustls-aws-lc-rs"),
    not(feature = "blocking-tls-native")
))]
compile_error!(
    "blocking transport requires one blocking TLS backend: enable `blocking-tls-rustls-ring`, `blocking-tls-rustls-aws-lc-rs`, or `blocking-tls-native`"
);

#[cfg(all(
    feature = "strict-feature-guards",
    feature = "_blocking",
    any(
        all(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs"
        ),
        all(feature = "blocking-tls-rustls-ring", feature = "blocking-tls-native"),
        all(
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-native"
        )
    )
))]
compile_error!(
    "blocking transport requires exactly one TLS backend: choose only one of `blocking-tls-rustls-ring`, `blocking-tls-rustls-aws-lc-rs`, or `blocking-tls-native`"
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
mod upload;

#[cfg(feature = "_async")]
pub(crate) use crate::async_client::body;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::client;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::limiters;
#[cfg(feature = "_async")]
pub(crate) use crate::async_client::request;
pub(crate) use crate::core::config;
pub(crate) use crate::core::content_encoding;
pub(crate) use crate::core::error;
pub(crate) use crate::core::execution;
pub(crate) use crate::core::extensions;
pub(crate) use crate::core::metrics;
pub(crate) use crate::core::observe;
pub(crate) use crate::core::otel;
pub(crate) use crate::core::policy;
pub(crate) use crate::core::proxy;
pub(crate) use crate::core::retry;
pub(crate) use crate::core::util;
pub(crate) use crate::http::response;

#[cfg(feature = "_async")]
pub use crate::client::{Client, ClientBuilder};
pub use crate::config::{AdvancedConfig, ClientProfile};
pub use crate::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
pub use crate::extensions::{
    BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer, PolicyBackoffSource,
    PrimaryEndpointSelector, RoundRobinEndpointSelector, StandardBodyCodec,
    StandardOtelPathNormalizer, SystemClock,
};
pub use crate::metrics::MetricsSnapshot;
pub use crate::observe::Observer;
pub use crate::policy::{Interceptor, RedirectPolicy, RequestContext, StatusPolicy};
pub use crate::rate_limit::{RateLimitPolicy, ServerThrottleScope};
#[cfg(feature = "_async")]
pub use crate::request::RequestBuilder;
pub use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy};
pub use crate::response::Response;
#[cfg(feature = "_async")]
pub use crate::response::ResponseStream;
#[cfg(feature = "_async")]
pub use crate::response::StreamBody;
pub use crate::retry::{
    PermissiveRetryEligibility, RetryClassifier, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
pub use crate::tls::{TlsBackend, TlsRootStore};
#[cfg(feature = "_async")]
pub use crate::upload::{AsyncResumableUploadBackend, AsyncResumableUploader};
pub use crate::upload::{
    BlockingResumableUploadBackend, BlockingResumableUploader, PartChecksumAlgorithm,
    RESUMABLE_UPLOAD_CHECKPOINT_VERSION, ResumableUploadCheckpoint, ResumableUploadError,
    ResumableUploadOptions, ResumableUploadResult, UploadedPart,
};

#[cfg(feature = "_blocking")]
pub mod blocking {
    pub use crate::blocking_client::{Client, ClientBuilder, RequestBuilder};
    pub use crate::response::BlockingResponseStream as ResponseStream;
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod prelude {
    pub mod sdk {
        #[cfg(feature = "_blocking")]
        pub use crate::blocking;
        #[cfg(feature = "_async")]
        pub use crate::{Client, ResponseStream};
        pub use crate::{
            Error, ErrorCode, RedirectPolicy, Response, Result, RetryPolicy, StatusPolicy,
            TlsBackend, TlsRootStore,
        };
    }

    pub mod advanced {
        pub use crate::{
            AdaptiveConcurrencyPolicy, AdvancedConfig, BackoffSource,
            BlockingResumableUploadBackend, BlockingResumableUploader, BodyCodec,
            CircuitBreakerPolicy, ClientProfile, Clock, EndpointSelector, Interceptor,
            MetricsSnapshot, Observer, OtelPathNormalizer, PartChecksumAlgorithm,
            PermissiveRetryEligibility, PolicyBackoffSource, PrimaryEndpointSelector,
            RESUMABLE_UPLOAD_CHECKPOINT_VERSION, RateLimitPolicy, RequestContext,
            ResumableUploadCheckpoint, ResumableUploadError, ResumableUploadOptions,
            ResumableUploadResult, RetryBudgetPolicy, RetryClassifier, RetryDecision,
            RetryEligibility, RoundRobinEndpointSelector, ServerThrottleScope, StandardBodyCodec,
            StandardOtelPathNormalizer, StrictRetryEligibility, SystemClock, TimeoutPhase,
            TransportErrorKind, UploadedPart,
        };
        #[cfg(feature = "_async")]
        pub use crate::{AsyncResumableUploadBackend, AsyncResumableUploader};
    }

    pub use sdk::*;
}

#[cfg(all(test, feature = "_async"))]
mod tests;
