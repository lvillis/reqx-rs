#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "_async", feature = "_blocking")), allow(dead_code))]
#![warn(missing_docs)]

//! `reqx` is a reusable HTTP transport crate for Rust API SDKs with retry,
//! timeout, idempotency, proxy, streaming, and pluggable TLS backends.
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
//! - Reach for [`advanced`] when you need non-default transport controls.
//!
//! # Common Tasks
//!
//! Start from these entry points:
//!
//! - Build an async client: [`Client::builder`]
//! - Build a blocking client: `reqx::blocking::Client::builder(...)`
//! - Prepare requests: [`RequestBuilder`] and `reqx::blocking::RequestBuilder`
//! - Handle buffered responses: [`Response`]
//! - Handle streaming responses: [`ResponseStream`] and `reqx::blocking::ResponseStream`
//! - Tune retries: [`prelude::RetryPolicy`] and [`advanced::RetryClassifier`]
//! - Configure TLS: [`TlsBackend`], [`TlsVersion`], and [`TlsRootStore`]
//! - Add advanced hooks: [`advanced::Interceptor`], [`advanced::Observer`], and [`advanced::EndpointSelector`]
//!
//! # Feature Selection
//!
//! Transport modes are selected through concrete transport+TLS feature flags:
//!
//! - Async + `rustls` + `ring`: `async-tls-rustls-ring`
//! - Async + `rustls` + `aws-lc-rs`: `async-tls-rustls-aws-lc-rs`
//! - Async + `native-tls`: `async-tls-native`
//! - Blocking + `ureq` + `rustls` + `ring`: `blocking-tls-rustls-ring`
//! - Blocking + `ureq` + `rustls` + `aws-lc-rs`: `blocking-tls-rustls-aws-lc-rs`
//! - Blocking + `ureq` + `native-tls`: `blocking-tls-native`
//!
//! The docs.rs build enables `async-tls-rustls-ring` and
//! `blocking-tls-rustls-ring`, so async and blocking entry points are both
//! visible there.
//!
//! # Cookbook
//!
//! Scenario-focused examples ship in `examples/`:
//!
//! - JSON request flow: `examples/basic_json.rs`
//! - Per-request overrides: `examples/request_overrides.rs`
//! - Streaming uploads/downloads: `examples/streaming.rs` and `examples/blocking_streaming.rs`
//! - Proxy and `no_proxy`: `examples/proxy_and_no_proxy.rs`
//! - TLS backend selection and mTLS: `examples/tls_backends.rs` and `examples/custom_ca_mtls.rs`
//! - Metrics and observers: `examples/metrics_snapshot.rs` and `examples/profile_and_observer.rs`
//! - Retry and resilience controls: `examples/resilience_controls.rs`, `examples/retry_classifier.rs`, and `examples/rate_limit_429.rs`
//! - Resumable uploads: `examples/resumable_upload.rs`
//!
//! The full scenario index lives in `examples/README.md`.
//!
//! # TLS Backend Notes
//!
//! - Async `rustls` backends support TLS version bounds via
//!   `Client::builder(...).tls_version(...)`,
//!   `Client::builder(...).tls_min_version(...)`, and
//!   `Client::builder(...).tls_max_version(...)`.
//! - Async `native-tls` currently supports only explicit TLS 1.2 constraints
//!   and does not support [`TlsRootStore::WebPki`].
//! - Blocking `ureq` transport currently rejects TLS version bounds at
//!   `build()` time.
//! - Custom root CAs require [`TlsRootStore::System`] or
//!   [`TlsRootStore::Specific`].

#[cfg(all(
    feature = "strict-feature-guards",
    not(feature = "_all-features-compat"),
    not(any(feature = "_async", feature = "_blocking"))
))]
compile_error!(
    "reqx requires at least one transport feature: enable an `async-tls-*` or `blocking-tls-*` feature"
);

#[cfg(all(
    feature = "strict-feature-guards",
    not(feature = "_all-features-compat"),
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
    not(feature = "_all-features-compat"),
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
    not(feature = "_all-features-compat"),
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
    not(feature = "_all-features-compat"),
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
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) use crate::core::execution;
pub(crate) use crate::core::extensions;
pub(crate) use crate::core::metrics;
pub(crate) use crate::core::observe;
pub(crate) use crate::core::otel;
pub(crate) use crate::core::policy;
#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) use crate::core::proxy;
pub(crate) use crate::core::retry;
pub(crate) use crate::core::util;
pub(crate) use crate::http::response;

#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub use crate::client::{Client, ClientBuilder};
pub use crate::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub use crate::request::RequestBuilder;
pub use crate::response::Response;
#[cfg(feature = "_async")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
pub use crate::response::ResponseStream;
pub use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};

#[cfg(feature = "_blocking")]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-native"
    )))
)]
/// Blocking transport API.
///
/// This mirrors the async surface where the underlying transport supports the
/// same behavior, but uses synchronous request execution and response streams.
pub mod blocking {
    pub use crate::blocking_client::{Client, ClientBuilder, RequestBuilder};
    pub use crate::response::BlockingResponseStream as ResponseStream;
}

/// Convenient result alias used by `reqx` APIs.
pub type Result<T> = std::result::Result<T, Error>;

/// Recommended imports for most SDK transport code.
pub mod prelude {
    pub use crate::Result;
    #[cfg(feature = "_blocking")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-native"
        )))
    )]
    pub use crate::blocking;
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::client::Client;
    pub use crate::error::{Error, ErrorCode};
    pub use crate::policy::{RedirectPolicy, StatusPolicy};
    pub use crate::response::Response;
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::response::ResponseStream;
    pub use crate::retry::RetryPolicy;
    pub use crate::tls::{TlsBackend, TlsRootStore, TlsVersion};
}

/// Advanced transport controls and extensibility points.
pub mod advanced {
    pub use crate::config::ClientProfile;
    pub use crate::error::{TimeoutPhase, TransportErrorKind};
    pub use crate::extensions::{
        BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer, PolicyBackoffSource,
        PrimaryEndpointSelector, RoundRobinEndpointSelector, StandardBodyCodec,
        StandardOtelPathNormalizer, SystemClock,
    };
    #[cfg(feature = "_async")]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs",
            feature = "async-tls-native"
        )))
    )]
    pub use crate::upload::{AsyncResumableUploadBackend, AsyncResumableUploader};
    pub use crate::{
        metrics::{
            ErrorMetrics, LatencyMetrics, MetricsSnapshot, RequestMetrics, ResponseMetrics,
            TimeoutMetrics,
        },
        observe::Observer,
        policy::{Interceptor, RedirectPolicy, RequestContext, StatusPolicy},
        rate_limit::{RateLimitPolicy, ServerThrottleScope},
        resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy},
        retry::{
            PermissiveRetryEligibility, RetryClassifier, RetryDecision, RetryEligibility,
            RetryReason, StrictRetryEligibility,
        },
        tls::{TlsBackend, TlsRootStore, TlsVersion},
        upload::{
            BlockingResumableUploadBackend, BlockingResumableUploader, PartChecksumAlgorithm,
            RESUMABLE_UPLOAD_CHECKPOINT_VERSION, ResumableUploadCheckpoint, ResumableUploadError,
            ResumableUploadOptions, ResumableUploadResult, UploadedPart,
        },
    };
}

#[cfg(all(test, feature = "_async"))]
mod tests;
