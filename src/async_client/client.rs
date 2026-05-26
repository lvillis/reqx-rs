use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, HeaderName, HeaderValue, PROXY_AUTHORIZATION,
};
use http::{HeaderMap, Method, Request, Response as HttpResponse, Uri};
use hyper::body::Incoming;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_util::rt::TokioExecutor;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout, timeout_at};
use tracing::{Instrument, debug, info_span, warn};

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_rustls::HttpsConnectorBuilder;

use crate::body::{
    ReadBodyError, ReqBody, RequestBody, buffered_req_body, build_http_request, empty_req_body,
    read_all_body_limited,
};
use crate::config::{
    ClientCommonBuildConfig, ClientConcurrencyLimits, ClientControlPolicies, ClientProfile,
    ClientTimeoutConfig,
};
use crate::content_encoding::should_decode_content_encoded_body;
use crate::core::request_builder::{RequestExecutionDefaults, RequestExecutionOptions};
use crate::error::{Error, TransportErrorKind, transport_error};
use crate::execution::{
    AttemptGuards, BodyReadFailure, BodyReadOutcome, BodyReadRetryContext, RequestCompletion,
    RequestExecutionPreparation, RequestExecutionState, RequestExecutionStateInput, ResponseMode,
    ResponseProgress, RetryAttemptState, RetryRequestInput, RetrySchedule, TransportFailurePlan,
    prepare_retry_request_input, server_throttle_delay,
};
use crate::extensions::{
    BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer, PolicyBackoffSource,
    PrimaryEndpointSelector, StandardBodyCodec, StandardOtelPathNormalizer, SystemClock,
};
use crate::limiters::{GlobalRequestPermit, HostRequestPermit, RequestLimiters};
use crate::metrics::{ClientMetrics, MetricsSnapshot};
use crate::observe::Observer;
use crate::otel::OtelTelemetry;
use crate::policy::{Interceptor, RedirectPolicy, RequestContext, StatusPolicy};
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use crate::proxy::ProxyConnector;
use crate::proxy::{
    NoProxyRule, ProxyConfig, parse_no_proxy_rule, parse_no_proxy_rules,
    redact_no_proxy_rule_for_logs, should_bypass_proxy_uri,
};
use crate::rate_limit::{
    RateLimitPolicy, RateLimiter, ServerThrottleScope, resolve_server_throttle_scope,
    server_throttle_scope_from_headers,
};
use crate::request::RequestBuilder;
use crate::resilience::{
    AdaptiveConcurrencyOutcome, AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState,
    CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
};
use crate::response::{
    DEFAULT_STREAM_DEADLINE_SLACK, Response, ResponseStream, ResponseStreamContext,
    StreamLifecycle, StreamPermits,
};
use crate::retry::{
    PermissiveRetryEligibility, RetryDecision, RetryEligibility, RetryPolicy, RetryReason,
    StrictRetryEligibility,
};
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native"
))]
use crate::tls::tls_config_error;
use crate::tls::{
    TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore, TlsVersion,
    tls_version_bounds,
};
use crate::util::{
    bounded_retry_delay, classify_transport_error, deadline_exceeded_error,
    duration_millis_u64_saturating, ensure_accept_encoding_async, lock_unpoisoned,
    parse_header_name, parse_header_value, redact_uri_for_logs, total_timeout_deadline,
    validate_base_url, validate_http_proxy_uri,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
const DEFAULT_CLIENT_NAME: &str = "reqx";
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "async-tls-rustls-ring")]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;
#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    feature = "async-tls-rustls-aws-lc-rs"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsAwsLcRs;
#[cfg(all(
    not(feature = "async-tls-rustls-ring"),
    not(feature = "async-tls-rustls-aws-lc-rs"),
    feature = "async-tls-native"
))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::NativeTls;
#[cfg(not(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native"
)))]
const DEFAULT_TLS_BACKEND: TlsBackend = TlsBackend::RustlsRing;

fn default_tls_backend() -> TlsBackend {
    DEFAULT_TLS_BACKEND
}

#[cfg(feature = "async-tls-native")]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(feature = "async-tls-native")]
fn extract_pem_certificate_blocks(pem_bundle: &[u8]) -> Vec<Vec<u8>> {
    const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(begin_offset) = find_subslice(&pem_bundle[cursor..], PEM_BEGIN) {
        let begin = cursor + begin_offset;
        let end_search_start = begin + PEM_BEGIN.len();
        let Some(end_offset) = find_subslice(&pem_bundle[end_search_start..], PEM_END) else {
            break;
        };
        let end = end_search_start + end_offset + PEM_END.len();
        let mut block_end = end;
        while block_end < pem_bundle.len()
            && (pem_bundle[block_end] == b'\n' || pem_bundle[block_end] == b'\r')
        {
            block_end += 1;
        }
        blocks.push(pem_bundle[begin..block_end].to_vec());
        cursor = block_end;
    }

    blocks
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
fn add_custom_rustls_root_certificates(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
    root_store: &mut rustls::RootCertStore,
) -> crate::Result<usize> {
    use rustls::pki_types::pem::PemObject;

    let mut added_total = 0usize;
    for certificate in &tls_options.root_certificates {
        match certificate {
            TlsRootCertificate::Pem(pem) => {
                let mut parsed = Vec::new();
                for item in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
                    let certificate = item.map_err(|source| {
                        tls_config_error(
                            tls_backend,
                            format!("failed to parse PEM root certificate: {source}"),
                        )
                    })?;
                    parsed.push(certificate);
                }
                if parsed.is_empty() {
                    return Err(tls_config_error(
                        tls_backend,
                        "no certificate blocks found in PEM root certificate",
                    ));
                }
                let (added, _ignored) = root_store.add_parsable_certificates(parsed);
                if added == 0 {
                    return Err(tls_config_error(
                        tls_backend,
                        "failed to parse PEM root certificate(s)",
                    ));
                }
                added_total = added_total.saturating_add(added);
            }
            TlsRootCertificate::Der(der) => {
                root_store
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|source| {
                        tls_config_error(
                            tls_backend,
                            format!("failed to add DER root certificate: {source}"),
                        )
                    })?;
                added_total = added_total.saturating_add(1);
            }
        }
    }

    Ok(added_total)
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
fn build_rustls_root_store(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<rustls::RootCertStore> {
    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            tls_backend,
            "custom root CAs require tls_root_store(TlsRootStore::WebPki), tls_root_store(TlsRootStore::System), or tls_root_store(TlsRootStore::Specific)",
        ));
    }

    let mut root_store = match tls_options.root_store {
        TlsRootStore::BackendDefault | TlsRootStore::WebPki => {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        }
        TlsRootStore::System | TlsRootStore::Specific => rustls::RootCertStore::empty(),
    };

    if tls_options.root_store == TlsRootStore::Specific && tls_options.root_certificates.is_empty()
    {
        return Err(tls_config_error(
            tls_backend,
            "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
        ));
    }

    let mut system_added = 0usize;
    if tls_options.root_store == TlsRootStore::System {
        let loaded = rustls_native_certs::load_native_certs();
        if !loaded.errors.is_empty() {
            warn!(
                backend = tls_backend.as_str(),
                error_count = loaded.errors.len(),
                "system root certificate loading returned partial errors"
            );
        }
        let (added, _ignored) = root_store.add_parsable_certificates(loaded.certs);
        system_added = added;
    }

    let custom_added = if matches!(
        tls_options.root_store,
        TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
    ) && !tls_options.root_certificates.is_empty()
    {
        add_custom_rustls_root_certificates(tls_backend, tls_options, &mut root_store)?
    } else {
        0
    };

    if tls_options.root_store == TlsRootStore::System && system_added + custom_added == 0 {
        return Err(tls_config_error(
            tls_backend,
            "failed to load system root certificates",
        ));
    }

    Ok(root_store)
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
pub(crate) fn configured_rustls_protocol_versions(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    let bounds = tls_version_bounds(tls_backend, tls_options)?;
    let versions = [TlsVersion::V1_3, TlsVersion::V1_2]
        .into_iter()
        .filter(|version| bounds.contains(*version))
        .collect::<Vec<_>>();

    Ok(versions
        .into_iter()
        .map(|version| match version {
            TlsVersion::V1_2 => &rustls::version::TLS12,
            TlsVersion::V1_3 => &rustls::version::TLS13,
        })
        .collect())
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
fn build_rustls_tls_config(
    tls_backend: TlsBackend,
    provider: impl Into<Arc<rustls::crypto::CryptoProvider>>,
    tls_options: &TlsOptions,
) -> crate::Result<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;

    let root_store = build_rustls_root_store(tls_backend, tls_options)?;
    let protocol_versions = configured_rustls_protocol_versions(tls_backend, tls_options)?;

    let config_builder = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&protocol_versions)
        .map_err(|source| Error::TlsBackendInit {
            backend: tls_backend.as_str(),
            message: source.to_string(),
        })?
        .with_root_certificates(root_store);

    match &tls_options.client_identity {
        None => Ok(config_builder.with_no_client_auth()),
        Some(TlsClientIdentity::Pem {
            cert_chain_pem,
            private_key_pem,
        }) => {
            let mut cert_chain = Vec::new();
            for item in rustls::pki_types::CertificateDer::pem_slice_iter(cert_chain_pem) {
                let certificate = item.map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to parse mTLS certificate chain PEM: {source}"),
                    )
                })?;
                cert_chain.push(certificate);
            }
            if cert_chain.is_empty() {
                return Err(tls_config_error(
                    tls_backend,
                    "mTLS certificate chain PEM is empty or invalid",
                ));
            }
            let private_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(private_key_pem)
                .map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to parse mTLS private key PEM: {source}"),
                    )
                })?;
            config_builder
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|source| {
                    tls_config_error(
                        tls_backend,
                        format!("failed to configure mTLS identity: {source}"),
                    )
                })
        }
        Some(TlsClientIdentity::Pkcs12 {
            identity_der,
            password,
        }) => Err(tls_config_error(
            tls_backend,
            format!(
                "PKCS#12 identity is unsupported for rustls backends; use PEM cert+key (pkcs12_bytes={}, password_len={})",
                identity_der.len(),
                password.len()
            ),
        )),
    }
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
type RustlsHttpsConnector = hyper_rustls::HttpsConnector<ProxyConnector>;
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
type RustlsHyperClient = HyperClient<RustlsHttpsConnector, ReqBody>;

#[cfg(feature = "async-tls-native")]
type NativeHttpsConnector = hyper_tls::HttpsConnector<ProxyConnector>;
#[cfg(feature = "async-tls-native")]
type NativeHyperClient = HyperClient<NativeHttpsConnector, ReqBody>;

#[derive(Clone)]
enum TransportClient {
    #[cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    Rustls(RustlsHyperClient),
    #[cfg(feature = "async-tls-native")]
    Native(NativeHyperClient),
}

impl TransportClient {
    async fn request(
        &self,
        request: Request<ReqBody>,
    ) -> Result<HttpResponse<Incoming>, hyper_util::client::legacy::Error> {
        #[cfg(any(
            feature = "async-tls-native",
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs"
        ))]
        {
            match self {
                #[cfg(any(
                    feature = "async-tls-rustls-ring",
                    feature = "async-tls-rustls-aws-lc-rs"
                ))]
                Self::Rustls(client) => client.request(request).await,
                #[cfg(feature = "async-tls-native")]
                Self::Native(client) => client.request(request).await,
            }
        }
        #[cfg(not(any(
            feature = "async-tls-native",
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs"
        )))]
        {
            let _ = request;
            match self {
                _ => unreachable!("no TLS transport backend is compiled"),
            }
        }
    }
}

enum TransportRequestError {
    Transport(hyper_util::client::legacy::Error),
    Timeout,
}

impl TransportRequestError {
    fn into_error(self, execution: &RequestExecutionState, transport_timeout: Duration) -> Error {
        match self {
            Self::Transport(source) => transport_error(
                classify_transport_error(&source),
                execution.current_method().clone(),
                execution.current_redacted_uri().to_owned(),
                source,
            ),
            Self::Timeout => execution.transport_timeout_error(transport_timeout.as_millis()),
        }
    }
}

enum RetryResponse {
    Buffered(Response),
    Stream(Box<ResponseStream>),
}

fn response_mode_mismatch_error(method: &Method, redacted_uri: &str, expected_mode: &str) -> Error {
    transport_error(
        TransportErrorKind::Other,
        method.clone(),
        redacted_uri.to_owned(),
        std::io::Error::other(format!(
            "internal response mode mismatch: expected {expected_mode} response variant"
        )),
    )
}

fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

struct StreamResponseInput {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: Incoming,
    method: Method,
    uri: Uri,
    redacted_uri: String,
    transport_timeout: Duration,
    stream_total_timeout_ms: Option<u128>,
    stream_deadline_at: Option<Instant>,
    stream_deadline_slack: Duration,
    stream_lifecycle: Option<StreamLifecycle>,
    stream_global_permit: Option<GlobalRequestPermit>,
    host_permit: HostRequestPermit,
}

struct StreamResponseBuildInput<'a> {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: Incoming,
    execution: &'a RequestExecutionState,
    transport_timeout: Duration,
    stream_total_timeout_ms: Option<u128>,
    stream_deadline_at: Option<Instant>,
    stream_lifecycle: Option<StreamLifecycle>,
    stream_global_permit: &'a mut Option<GlobalRequestPermit>,
    host_permit: HostRequestPermit,
}

fn stream_retry_response(input: StreamResponseInput) -> RetryResponse {
    let StreamResponseInput {
        status,
        response_headers,
        response_body,
        method,
        uri,
        redacted_uri,
        transport_timeout,
        stream_total_timeout_ms,
        stream_deadline_at,
        stream_deadline_slack,
        stream_lifecycle,
        stream_global_permit,
        host_permit,
    } = input;
    RetryResponse::Stream(Box::new(ResponseStream::new(
        status,
        response_headers,
        response_body,
        ResponseStreamContext {
            method,
            uri_raw: uri.to_string(),
            uri_redacted: redacted_uri,
            timeout_ms: transport_timeout.as_millis(),
            total_timeout_ms: stream_total_timeout_ms,
            deadline_at: stream_deadline_at,
            deadline_slack: stream_deadline_slack,
            lifecycle: stream_lifecycle,
            permits: StreamPermits::new(stream_global_permit, Some(host_permit)),
        },
    )))
}

#[cfg(feature = "async-tls-rustls-ring")]
fn build_rustls_ring_transport(
    proxy_config: Option<ProxyConfig>,
    tls_options: &TlsOptions,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let connector = ProxyConnector::new(proxy_config, connect_timeout);
    let tls_config = build_rustls_tls_config(
        TlsBackend::RustlsRing,
        rustls::crypto::ring::default_provider(),
        tls_options,
    )?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Rustls(transport))
}

#[cfg(not(feature = "async-tls-rustls-ring"))]
fn build_rustls_ring_transport(
    _proxy_config: Option<ProxyConfig>,
    _tls_options: &TlsOptions,
    _connect_timeout: Duration,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::RustlsRing.as_str(),
    })
}

#[cfg(feature = "async-tls-rustls-aws-lc-rs")]
fn build_rustls_aws_lc_rs_transport(
    proxy_config: Option<ProxyConfig>,
    tls_options: &TlsOptions,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let connector = ProxyConnector::new(proxy_config, connect_timeout);
    let tls_config = build_rustls_tls_config(
        TlsBackend::RustlsAwsLcRs,
        rustls::crypto::aws_lc_rs::default_provider(),
        tls_options,
    )?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(connector);
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Rustls(transport))
}

#[cfg(not(feature = "async-tls-rustls-aws-lc-rs"))]
fn build_rustls_aws_lc_rs_transport(
    _proxy_config: Option<ProxyConfig>,
    _tls_options: &TlsOptions,
    _connect_timeout: Duration,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::RustlsAwsLcRs.as_str(),
    })
}

#[cfg(feature = "async-tls-native")]
fn native_tls_protocol(version: TlsVersion) -> hyper_tls::native_tls::Protocol {
    match version {
        TlsVersion::V1_2 => hyper_tls::native_tls::Protocol::Tlsv12,
        TlsVersion::V1_3 => hyper_tls::native_tls::Protocol::Tlsv13,
    }
}

#[cfg(feature = "async-tls-native")]
fn apply_native_tls_protocol_versions(
    connector_builder: &mut hyper_tls::native_tls::TlsConnectorBuilder,
    tls_options: &TlsOptions,
) -> crate::Result<()> {
    let bounds = tls_version_bounds(TlsBackend::NativeTls, tls_options)?;
    if bounds.min.is_none() && bounds.max.is_none() {
        return Ok(());
    }

    if let Some(min) = bounds.min {
        connector_builder.min_protocol_version(Some(native_tls_protocol(min)));
    }

    if let Some(max) = bounds.max {
        connector_builder.max_protocol_version(Some(native_tls_protocol(max)));
    }

    Ok(())
}

#[cfg(feature = "async-tls-native")]
fn build_native_tls_connector(
    tls_options: &TlsOptions,
) -> crate::Result<hyper_tls::native_tls::TlsConnector> {
    let mut connector_builder = hyper_tls::native_tls::TlsConnector::builder();

    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::WebPki | TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            TlsBackend::NativeTls,
            "custom root CAs require tls_root_store(TlsRootStore::WebPki), tls_root_store(TlsRootStore::System), or tls_root_store(TlsRootStore::Specific)",
        ));
    }

    match tls_options.root_store {
        TlsRootStore::BackendDefault | TlsRootStore::System => {
            connector_builder.disable_built_in_roots(false);
        }
        TlsRootStore::Specific => {
            if tls_options.root_certificates.is_empty() {
                return Err(tls_config_error(
                    TlsBackend::NativeTls,
                    "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
                ));
            }
            connector_builder.disable_built_in_roots(true);
        }
        TlsRootStore::WebPki => {
            return Err(tls_config_error(
                TlsBackend::NativeTls,
                "tls_root_store(TlsRootStore::WebPki) is unsupported for native-tls backend; use System or Specific",
            ));
        }
    }

    for certificate in &tls_options.root_certificates {
        match certificate {
            TlsRootCertificate::Pem(pem) => {
                let certificate_blocks = extract_pem_certificate_blocks(pem);
                if certificate_blocks.is_empty() {
                    return Err(tls_config_error(
                        TlsBackend::NativeTls,
                        "no certificate blocks found in PEM root certificate",
                    ));
                }
                for certificate_block in certificate_blocks {
                    let certificate = hyper_tls::native_tls::Certificate::from_pem(
                        &certificate_block,
                    )
                    .map_err(|source| {
                        tls_config_error(
                            TlsBackend::NativeTls,
                            format!("failed to parse PEM root certificate: {source}"),
                        )
                    })?;
                    connector_builder.add_root_certificate(certificate);
                }
            }
            TlsRootCertificate::Der(der) => {
                let certificate =
                    hyper_tls::native_tls::Certificate::from_der(der).map_err(|source| {
                        tls_config_error(
                            TlsBackend::NativeTls,
                            format!("failed to parse DER root certificate: {source}"),
                        )
                    })?;
                connector_builder.add_root_certificate(certificate);
            }
        }
    }

    if let Some(identity) = &tls_options.client_identity {
        let identity = match identity {
            TlsClientIdentity::Pem {
                cert_chain_pem,
                private_key_pem,
            } => hyper_tls::native_tls::Identity::from_pkcs8(cert_chain_pem, private_key_pem)
                .map_err(|source| {
                    tls_config_error(
                        TlsBackend::NativeTls,
                        format!("failed to parse PKCS#8 mTLS identity: {source}"),
                    )
                })?,
            TlsClientIdentity::Pkcs12 {
                identity_der,
                password,
            } => hyper_tls::native_tls::Identity::from_pkcs12(identity_der, password).map_err(
                |source| {
                    tls_config_error(
                        TlsBackend::NativeTls,
                        format!("failed to parse PKCS#12 mTLS identity: {source}"),
                    )
                },
            )?,
        };
        connector_builder.identity(identity);
    }

    apply_native_tls_protocol_versions(&mut connector_builder, tls_options)?;

    connector_builder
        .build()
        .map_err(|source| Error::TlsBackendInit {
            backend: TlsBackend::NativeTls.as_str(),
            message: source.to_string(),
        })
}

#[cfg(feature = "async-tls-native")]
fn build_native_tls_transport(
    proxy_config: Option<ProxyConfig>,
    tls_options: &TlsOptions,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    let connector = ProxyConnector::new(proxy_config, connect_timeout);
    let https = if tls_options.has_customizations() {
        let tls_connector = build_native_tls_connector(tls_options)?;
        hyper_tls::HttpsConnector::from((connector, tls_connector.into()))
    } else {
        hyper_tls::HttpsConnector::new_with_connector(connector)
    };
    let transport = HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Native(transport))
}

#[cfg(not(feature = "async-tls-native"))]
fn build_native_tls_transport(
    _proxy_config: Option<ProxyConfig>,
    _tls_options: &TlsOptions,
    _connect_timeout: Duration,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> crate::Result<TransportClient> {
    Err(Error::TlsBackendUnavailable {
        backend: TlsBackend::NativeTls.as_str(),
    })
}

fn build_transport_client(
    tls_backend: TlsBackend,
    proxy_config: Option<ProxyConfig>,
    tls_options: &TlsOptions,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> crate::Result<TransportClient> {
    match tls_backend {
        TlsBackend::RustlsRing => build_rustls_ring_transport(
            proxy_config,
            tls_options,
            connect_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::RustlsAwsLcRs => build_rustls_aws_lc_rs_transport(
            proxy_config,
            tls_options,
            connect_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::NativeTls => build_native_tls_transport(
            proxy_config,
            tls_options,
            connect_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
    }
}

struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    clock: Arc<dyn Clock>,
    notify: Notify,
}

impl AdaptiveConcurrencyController {
    fn new(policy: AdaptiveConcurrencyPolicy, clock: Arc<dyn Clock>) -> Self {
        let policy = policy.normalize_for_runtime();
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState::new(policy)),
            clock,
            notify: Notify::new(),
        }
    }

    async fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // `notify_waiters` does not store a permit for futures that have not
            // been registered yet. Enable before checking capacity so a release
            // racing with this check cannot be lost.
            notified.as_mut().enable();
            {
                let mut state = lock_unpoisoned(&self.state);
                if state.try_acquire() {
                    return AdaptiveConcurrencyPermit {
                        controller: Arc::clone(self),
                        started_at: self.clock.now_monotonic(),
                        completed: false,
                    };
                }
            }
            notified.await;
        }
    }

    fn release_and_record(&self, outcome: AdaptiveConcurrencyOutcome, latency: Duration) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_and_record(self.policy, outcome, latency);
        self.notify.notify_waiters();
    }

    fn release_without_record(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_without_record();
        self.notify.notify_waiters();
    }
}

struct AdaptiveConcurrencyPermit {
    controller: Arc<AdaptiveConcurrencyController>,
    started_at: Instant,
    completed: bool,
}

impl AdaptiveConcurrencyPermit {
    fn latency(&self) -> Duration {
        self.controller
            .clock
            .now_monotonic()
            .saturating_duration_since(self.started_at)
    }

    fn mark_success(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Success, self.latency());
        self.completed = true;
    }

    fn mark_failure(mut self) {
        self.controller
            .release_and_record(AdaptiveConcurrencyOutcome::Failure, self.latency());
        self.completed = true;
    }

    fn cancel(mut self) {
        self.controller.release_without_record();
        self.completed = true;
    }
}

impl crate::execution::AttemptOutcome for AdaptiveConcurrencyPermit {
    fn mark_success(self) {
        Self::mark_success(self);
    }

    fn mark_failure(self) {
        Self::mark_failure(self);
    }

    fn cancel(self) {
        Self::cancel(self);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        if !self.completed {
            self.controller
                .release_and_record(AdaptiveConcurrencyOutcome::Failure, self.latency());
            self.completed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{AdaptiveConcurrencyController, AdaptiveConcurrencyPolicy, SystemClock};

    #[tokio::test]
    async fn adaptive_controller_unblocks_waiter_after_release() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(1)
            .max_limit(1);
        let controller = Arc::new(AdaptiveConcurrencyController::new(
            policy,
            Arc::new(SystemClock),
        ));

        let first_permit = controller.acquire().await;
        let waiter = {
            let controller = Arc::clone(&controller);
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_millis(300), controller.acquire())
                    .await
                    .is_ok()
            })
        };

        tokio::task::yield_now().await;
        drop(first_permit);

        let completed = waiter.await.expect("waiter task should join");
        assert!(completed, "waiter should acquire after permit release");
    }
}

#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
/// Builds an async [`Client`] with transport, timeout, retry, TLS, and
/// observability settings.
///
/// Start from [`Client::builder`] and override only the controls your SDK
/// actually needs.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "_async")]
/// # async fn demo() -> reqx::Result<()> {
/// use std::time::Duration;
///
/// use reqx::advanced::RateLimitPolicy;
/// use reqx::prelude::{Client, RetryPolicy};
/// use reqx::TlsVersion;
///
/// let client = Client::builder("https://api.example.com")
///     .request_timeout(Duration::from_secs(3))
///     .total_timeout(Duration::from_secs(10))
///     .retry_policy(RetryPolicy::standard())
///     .http_proxy("http://proxy.internal:8080".parse().unwrap())
///     .tls_max_version(TlsVersion::V1_2)
///     .global_rate_limit_policy(RateLimitPolicy::standard())
///     .build()?;
///
/// let _ = client;
/// # Ok(())
/// # }
/// ```
pub struct ClientBuilder {
    base_url: String,
    default_headers: HeaderMap,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    stream_deadline_slack: Duration,
    max_response_body_bytes: usize,
    connect_timeout: Duration,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
    http_proxy: Option<Uri>,
    proxy_authorization: Option<HeaderValue>,
    no_proxy_rules: Vec<NoProxyRule>,
    invalid_no_proxy_rules: Vec<String>,
    retry_policy: RetryPolicy,
    retry_eligibility: Arc<dyn RetryEligibility>,
    retry_budget_policy: Option<RetryBudgetPolicy>,
    circuit_breaker_policy: Option<CircuitBreakerPolicy>,
    adaptive_concurrency_policy: Option<AdaptiveConcurrencyPolicy>,
    global_rate_limit_policy: Option<RateLimitPolicy>,
    per_host_rate_limit_policy: Option<RateLimitPolicy>,
    server_throttle_scope: ServerThrottleScope,
    redirect_policy: RedirectPolicy,
    default_status_policy: StatusPolicy,
    tls_backend: TlsBackend,
    tls_options: TlsOptions,
    endpoint_selector: Arc<dyn EndpointSelector>,
    body_codec: Arc<dyn BodyCodec>,
    clock: Arc<dyn Clock>,
    backoff_source: Arc<dyn BackoffSource>,
    client_name: String,
    max_in_flight: Option<usize>,
    max_in_flight_per_host: Option<usize>,
    metrics_enabled: bool,
    otel_enabled: bool,
    otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}

impl ClientBuilder {
    pub(crate) fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            default_headers: HeaderMap::new(),
            buffered_auto_accept_encoding: true,
            stream_auto_accept_encoding: false,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            total_timeout: None,
            stream_deadline_slack: DEFAULT_STREAM_DEADLINE_SLACK,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            http2_only: false,
            http_proxy: None,
            proxy_authorization: None,
            no_proxy_rules: Vec::new(),
            invalid_no_proxy_rules: Vec::new(),
            retry_policy: RetryPolicy::standard(),
            retry_eligibility: Arc::new(StrictRetryEligibility),
            retry_budget_policy: None,
            circuit_breaker_policy: None,
            adaptive_concurrency_policy: None,
            global_rate_limit_policy: None,
            per_host_rate_limit_policy: None,
            server_throttle_scope: ServerThrottleScope::Auto,
            redirect_policy: RedirectPolicy::none(),
            default_status_policy: StatusPolicy::Error,
            tls_backend: default_tls_backend(),
            tls_options: TlsOptions::default(),
            endpoint_selector: Arc::new(PrimaryEndpointSelector),
            body_codec: Arc::new(StandardBodyCodec),
            clock: Arc::new(SystemClock),
            backoff_source: Arc::new(PolicyBackoffSource),
            client_name: DEFAULT_CLIENT_NAME.to_owned(),
            max_in_flight: None,
            max_in_flight_per_host: None,
            metrics_enabled: false,
            otel_enabled: false,
            otel_path_normalizer: Arc::new(StandardOtelPathNormalizer),
            interceptors: Vec::new(),
            observers: Vec::new(),
        }
    }

    /// Sets the per-attempt request timeout.
    ///
    /// A zero duration is rejected by [`Self::build`].
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    /// Sets the overall request deadline, including retries and redirects.
    ///
    /// A zero duration is rejected by [`Self::build`].
    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout);
        self
    }

    /// Tunes near-deadline classification for streaming body reads.
    ///
    /// This only affects how ambiguous boundary cases are classified between
    /// `Timeout(ResponseBody)` and `DeadlineExceeded` when the total deadline is
    /// already the tighter bound for the current read. The default is a small
    /// 10ms jitter buffer; changing it does not shorten the actual time spent
    /// waiting on the runtime's transport timers.
    pub fn stream_deadline_slack(mut self, stream_deadline_slack: Duration) -> Self {
        self.stream_deadline_slack = stream_deadline_slack;
        self
    }

    /// Sets the default buffered response body size limit in bytes.
    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = max_response_body_bytes;
        self
    }

    /// Sets the connect timeout used before a socket is established.
    ///
    /// A zero duration is rejected by [`Self::build`].
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Sets how long idle pooled connections may be kept alive.
    ///
    /// A zero duration disables idle connection retention.
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.pool_idle_timeout = pool_idle_timeout;
        self
    }

    /// Sets the maximum number of idle pooled connections kept per host.
    ///
    /// Zero disables per-host idle connection retention.
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.pool_max_idle_per_host = pool_max_idle_per_host;
        self
    }

    /// Forces HTTP/2 for all requests.
    pub fn http2_only(mut self, http2_only: bool) -> Self {
        self.http2_only = http2_only;
        self
    }

    /// Routes requests through the given HTTP proxy.
    ///
    /// Async transport does not read proxy credentials from the URI. Use
    /// [`Self::proxy_authorization`] for HTTP proxy authentication.
    pub fn http_proxy(mut self, proxy_uri: Uri) -> Self {
        self.http_proxy = Some(proxy_uri);
        self
    }

    /// Sets the `Proxy-Authorization` header sent to the configured HTTP proxy.
    pub fn proxy_authorization(mut self, mut proxy_authorization: HeaderValue) -> Self {
        proxy_authorization.set_sensitive(true);
        self.proxy_authorization = Some(proxy_authorization);
        self
    }

    /// Parses and sets the `Proxy-Authorization` header.
    pub fn try_proxy_authorization(self, proxy_authorization: &str) -> crate::Result<Self> {
        let proxy_authorization = parse_header_value("proxy-authorization", proxy_authorization)?;
        Ok(self.proxy_authorization(proxy_authorization))
    }

    /// Replaces the current `no_proxy` rule set.
    pub fn no_proxy<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.no_proxy_rules.clear();
        self.invalid_no_proxy_rules.clear();
        for rule in rules {
            let raw = rule.as_ref();
            match NoProxyRule::parse(raw) {
                Some(rule) => self.no_proxy_rules.push(rule),
                None => self
                    .invalid_no_proxy_rules
                    .push(redact_no_proxy_rule_for_logs(raw)),
            }
        }
        self
    }

    /// Replaces the current `no_proxy` rule set and validates every rule.
    pub fn try_no_proxy<I, S>(mut self, rules: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.no_proxy_rules = parse_no_proxy_rules(rules)?;
        self.invalid_no_proxy_rules.clear();
        Ok(self)
    }

    /// Appends one `no_proxy` rule, deferring validation errors to [`Self::build`].
    pub fn add_no_proxy(mut self, rule: impl AsRef<str>) -> Self {
        let raw = rule.as_ref();
        if let Some(rule) = NoProxyRule::parse(raw) {
            self.no_proxy_rules.push(rule);
        } else {
            self.invalid_no_proxy_rules
                .push(redact_no_proxy_rule_for_logs(raw));
        }
        self
    }

    /// Appends and validates one `no_proxy` rule immediately.
    pub fn try_add_no_proxy(mut self, rule: impl AsRef<str>) -> crate::Result<Self> {
        self.no_proxy_rules
            .push(parse_no_proxy_rule(rule.as_ref())?);
        Ok(self)
    }

    /// Adds a default header included with every request.
    pub fn default_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.default_headers.insert(name, value);
        self
    }

    /// Enables or disables automatic `Accept-Encoding` injection for all request modes.
    pub fn auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self.stream_auto_accept_encoding = enabled;
        self
    }

    /// Enables or disables automatic `Accept-Encoding` for buffered responses.
    pub fn buffered_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self
    }

    /// Enables or disables automatic `Accept-Encoding` for streaming responses.
    pub fn stream_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.stream_auto_accept_encoding = enabled;
        self
    }

    /// Parses and adds a default header included with every request.
    pub fn try_default_header(self, name: &str, value: &str) -> crate::Result<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.default_header(name, value))
    }

    /// Sets the default retry policy.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Sets the predicate that decides whether a failure may be retried.
    pub fn retry_eligibility(mut self, retry_eligibility: Arc<dyn RetryEligibility>) -> Self {
        self.retry_eligibility = retry_eligibility;
        self
    }

    /// Enables retry budget enforcement.
    pub fn retry_budget_policy(mut self, retry_budget_policy: RetryBudgetPolicy) -> Self {
        self.retry_budget_policy = Some(retry_budget_policy);
        self
    }

    /// Enables circuit breaker protection for upstream failures.
    pub fn circuit_breaker_policy(mut self, circuit_breaker_policy: CircuitBreakerPolicy) -> Self {
        self.circuit_breaker_policy = Some(circuit_breaker_policy);
        self
    }

    /// Enables adaptive concurrency control.
    pub fn adaptive_concurrency_policy(
        mut self,
        adaptive_concurrency_policy: AdaptiveConcurrencyPolicy,
    ) -> Self {
        self.adaptive_concurrency_policy = Some(adaptive_concurrency_policy);
        self
    }

    /// Applies a client-wide rate limit policy.
    pub fn global_rate_limit_policy(mut self, global_rate_limit_policy: RateLimitPolicy) -> Self {
        self.global_rate_limit_policy = Some(global_rate_limit_policy);
        self
    }

    /// Applies a host-scoped rate limit policy.
    pub fn per_host_rate_limit_policy(
        mut self,
        per_host_rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        self.per_host_rate_limit_policy = Some(per_host_rate_limit_policy);
        self
    }

    /// Chooses how server throttling hints are mapped onto configured rate limiters.
    pub fn server_throttle_scope(mut self, server_throttle_scope: ServerThrottleScope) -> Self {
        self.server_throttle_scope = server_throttle_scope;
        self
    }

    /// Sets the default redirect handling policy.
    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    /// Sets the default status handling policy for requests.
    pub fn default_status_policy(mut self, default_status_policy: StatusPolicy) -> Self {
        self.default_status_policy = default_status_policy;
        self
    }

    /// Selects the TLS backend used by this client.
    ///
    /// Async `rustls` backends support TLS version bounds. Async `native-tls`
    /// maps configured version bounds onto the platform TLS stack and rejects
    /// [`TlsRootStore::WebPki`] at build time.
    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
        self
    }

    /// Pins both the minimum and maximum TLS version to `version`.
    ///
    /// Async `rustls` backends accept both [`TlsVersion::V1_2`] and
    /// [`TlsVersion::V1_3`]. Async `native-tls` forwards the configured range
    /// to the underlying platform TLS implementation.
    pub fn tls_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.min_protocol_version = Some(version);
        self.tls_options.max_protocol_version = Some(version);
        self
    }

    /// Sets the minimum TLS version accepted for outbound connections.
    ///
    /// Async `native-tls` forwards the configured range to the underlying
    /// platform TLS implementation.
    pub fn tls_min_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.min_protocol_version = Some(version);
        self
    }

    /// Sets the maximum TLS version accepted for outbound connections.
    ///
    /// Async `native-tls` forwards the configured range to the underlying
    /// platform TLS implementation.
    pub fn tls_max_version(mut self, version: TlsVersion) -> Self {
        self.tls_options.max_protocol_version = Some(version);
        self
    }

    /// Sets the endpoint selector used for multi-endpoint clients.
    pub fn endpoint_selector_arc(mut self, endpoint_selector: Arc<dyn EndpointSelector>) -> Self {
        self.endpoint_selector = endpoint_selector;
        self
    }

    /// Sets the endpoint selector used for multi-endpoint clients.
    pub fn endpoint_selector<S>(self, endpoint_selector: S) -> Self
    where
        S: EndpointSelector + 'static,
    {
        self.endpoint_selector_arc(Arc::new(endpoint_selector))
    }

    /// Sets the body codec used by convenience request helpers.
    pub fn body_codec_arc(mut self, body_codec: Arc<dyn BodyCodec>) -> Self {
        self.body_codec = body_codec;
        self
    }

    /// Sets the body codec used by convenience request helpers.
    pub fn body_codec<C>(self, body_codec: C) -> Self
    where
        C: BodyCodec + 'static,
    {
        self.body_codec_arc(Arc::new(body_codec))
    }

    /// Sets the time source used by Retry-After parsing and internal control loops.
    ///
    /// This does not replace the runtime timers used for transport I/O.
    pub fn control_clock_arc(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets the time source used by Retry-After parsing and internal control loops.
    ///
    /// This does not replace the runtime timers used for transport I/O.
    pub fn control_clock<C>(self, clock: C) -> Self
    where
        C: Clock + 'static,
    {
        self.control_clock_arc(Arc::new(clock))
    }

    /// Sets the backoff source used for retry sleeps and server throttle waits.
    pub fn backoff_source_arc(mut self, backoff_source: Arc<dyn BackoffSource>) -> Self {
        self.backoff_source = backoff_source;
        self
    }

    /// Sets the backoff source used for retry sleeps and server throttle waits.
    pub fn backoff_source<B>(self, backoff_source: B) -> Self
    where
        B: BackoffSource + 'static,
    {
        self.backoff_source_arc(Arc::new(backoff_source))
    }

    /// Selects which root trust store the TLS backend should use.
    ///
    /// Custom root CAs require [`TlsRootStore::WebPki`],
    /// [`TlsRootStore::System`], or [`TlsRootStore::Specific`]. For rustls
    /// backends, [`TlsRootStore::WebPki`] appends explicit custom roots to the
    /// bundled Mozilla roots. Async `native-tls` rejects [`TlsRootStore::WebPki`].
    pub fn tls_root_store(mut self, tls_root_store: TlsRootStore) -> Self {
        self.tls_options.root_store = tls_root_store;
        self
    }

    /// Adds a PEM-encoded root CA certificate.
    ///
    /// Pair this with [`Self::tls_root_store`] set to
    /// [`TlsRootStore::WebPki`], [`TlsRootStore::System`], or
    /// [`TlsRootStore::Specific`]. With rustls and [`TlsRootStore::WebPki`],
    /// this appends to the bundled Mozilla roots.
    pub fn tls_root_ca_pem(mut self, certificate_pem: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Pem(certificate_pem.into()));
        self
    }

    /// Adds a DER-encoded root CA certificate.
    ///
    /// Pair this with [`Self::tls_root_store`] set to
    /// [`TlsRootStore::WebPki`], [`TlsRootStore::System`], or
    /// [`TlsRootStore::Specific`]. With rustls and [`TlsRootStore::WebPki`],
    /// this appends to the bundled Mozilla roots.
    pub fn tls_root_ca_der(mut self, certificate_der: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Der(certificate_der.into()));
        self
    }

    /// Removes all explicitly configured root CA certificates.
    pub fn clear_tls_root_cas(mut self) -> Self {
        self.tls_options.root_certificates.clear();
        self
    }

    /// Sets a PEM-encoded client certificate chain and private key for mTLS.
    pub fn tls_client_identity_pem(
        mut self,
        cert_chain_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.tls_options.client_identity = Some(TlsClientIdentity::Pem {
            cert_chain_pem: cert_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        });
        self
    }

    /// Sets a PKCS#12 client identity for mTLS.
    pub fn tls_client_identity_pkcs12(
        mut self,
        identity_der: impl Into<Vec<u8>>,
        password: impl Into<String>,
    ) -> Self {
        self.tls_options.client_identity = Some(TlsClientIdentity::Pkcs12 {
            identity_der: identity_der.into(),
            password: password.into(),
        });
        self
    }

    /// Removes any configured client TLS identity.
    pub fn clear_tls_client_identity(mut self) -> Self {
        self.tls_options.client_identity = None;
        self
    }

    /// Clears any configured TLS version bounds.
    pub fn clear_tls_version_bounds(mut self) -> Self {
        self.tls_options.min_protocol_version = None;
        self.tls_options.max_protocol_version = None;
        self
    }

    /// Allows retries for methods that are not normally considered idempotent.
    pub fn allow_non_idempotent_retries(mut self, allow: bool) -> Self {
        self.retry_eligibility = if allow {
            Arc::new(PermissiveRetryEligibility)
        } else {
            Arc::new(StrictRetryEligibility)
        };
        self
    }

    /// Sets the client name used in metrics, diagnostics, and default `User-Agent`.
    ///
    /// The value must be non-empty and valid as an HTTP header value.
    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = client_name.into();
        self
    }

    /// Caps the total number of in-flight requests.
    ///
    /// A zero limit is rejected by [`Self::build`]. Leave the option unset for
    /// no global in-flight limit.
    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = Some(max_in_flight);
        self
    }

    /// Caps the number of in-flight requests per host.
    ///
    /// A zero limit is rejected by [`Self::build`]. Leave the option unset for
    /// no per-host in-flight limit.
    pub fn max_in_flight_per_host(mut self, max_in_flight_per_host: usize) -> Self {
        self.max_in_flight_per_host = Some(max_in_flight_per_host);
        self
    }

    /// Enables in-process metrics collection.
    pub fn metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Enables OpenTelemetry observer emission.
    pub fn otel_enabled(mut self, enabled: bool) -> Self {
        self.otel_enabled = enabled;
        self
    }

    /// Sets the path normalizer used for OpenTelemetry attributes.
    pub fn otel_path_normalizer_arc(
        mut self,
        otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    ) -> Self {
        self.otel_path_normalizer = otel_path_normalizer;
        self
    }

    /// Sets the path normalizer used for OpenTelemetry attributes.
    pub fn otel_path_normalizer<N>(self, otel_path_normalizer: N) -> Self
    where
        N: OtelPathNormalizer + 'static,
    {
        self.otel_path_normalizer_arc(Arc::new(otel_path_normalizer))
    }

    /// Registers a request/response interceptor.
    pub fn interceptor_arc(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    /// Registers a request/response interceptor.
    pub fn interceptor<I>(self, interceptor: I) -> Self
    where
        I: Interceptor + 'static,
    {
        self.interceptor_arc(Arc::new(interceptor))
    }

    /// Registers an observer that receives lifecycle callbacks.
    pub fn observer_arc(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observers.push(observer);
        self
    }

    /// Registers an observer that receives lifecycle callbacks.
    pub fn observer<O>(self, observer: O) -> Self
    where
        O: Observer + 'static,
    {
        self.observer_arc(Arc::new(observer))
    }

    /// Applies a bundle of profile defaults.
    pub fn profile(mut self, profile: ClientProfile) -> Self {
        let defaults = profile.defaults();
        self.request_timeout = defaults.request_timeout;
        self.total_timeout = defaults.total_timeout;
        self.retry_policy = defaults.retry_policy;
        self.max_response_body_bytes = defaults.max_response_body_bytes;
        self.redirect_policy = defaults.redirect_policy;
        self.default_status_policy = defaults.status_policy;
        self
    }

    /// Validates the builder and constructs the client.
    ///
    /// Unsupported backend-specific TLS combinations return
    /// [`crate::Error::TlsConfig`].
    pub fn build(self) -> crate::Result<Client> {
        validate_base_url(&self.base_url)?;
        if let Some(proxy_uri) = self.http_proxy.as_ref() {
            validate_http_proxy_uri(proxy_uri)?;
            let proxy_uri_has_credentials = proxy_uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'));
            if proxy_uri_has_credentials {
                return Err(Error::InvalidProxyConfig {
                    proxy_uri: redact_uri_for_logs(&proxy_uri.to_string()),
                    message: "async http_proxy URI must not include credentials; use proxy_authorization(...) for HTTP proxy authentication".to_owned(),
                });
            }
        }
        if self.proxy_authorization.is_some() && self.http_proxy.is_none() {
            return Err(Error::ProxyAuthorizationRequiresHttpProxy);
        }
        let default_headers = ClientCommonBuildConfig {
            invalid_no_proxy_rule: self.invalid_no_proxy_rules.first().map(String::as_str),
            timeout_config: ClientTimeoutConfig {
                request_timeout: self.request_timeout,
                total_timeout: self.total_timeout,
                connect_timeout: self.connect_timeout,
            },
            concurrency_limits: ClientConcurrencyLimits {
                max_in_flight: self.max_in_flight,
                max_in_flight_per_host: self.max_in_flight_per_host,
            },
            retry_policy: &self.retry_policy,
            control_policies: ClientControlPolicies {
                retry_budget: self.retry_budget_policy,
                circuit_breaker: self.circuit_breaker_policy,
                adaptive_concurrency: self.adaptive_concurrency_policy,
                global_rate_limit: self.global_rate_limit_policy,
                per_host_rate_limit: self.per_host_rate_limit_policy,
            },
            client_name: &self.client_name,
            default_headers: self.default_headers,
        }
        .validate()?;

        let proxy_config = self.http_proxy.map(|uri| ProxyConfig {
            uri,
            authorization: self.proxy_authorization,
            no_proxy_rules: self.no_proxy_rules,
        });
        let transport = build_transport_client(
            self.tls_backend,
            proxy_config.clone(),
            &self.tls_options,
            self.connect_timeout,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.http2_only,
        )?;
        let otel = if self.otel_enabled {
            OtelTelemetry::enabled_with_path_normalizer(
                self.client_name.clone(),
                self.otel_path_normalizer,
            )
        } else {
            OtelTelemetry::disabled()
        };
        let clock = self.clock;

        Ok(Client {
            base_url: self.base_url,
            default_headers,
            buffered_auto_accept_encoding: self.buffered_auto_accept_encoding,
            stream_auto_accept_encoding: self.stream_auto_accept_encoding,
            request_timeout: self.request_timeout,
            total_timeout: self.total_timeout,
            stream_deadline_slack: self.stream_deadline_slack,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
            retry_eligibility: self.retry_eligibility,
            retry_budget: self
                .retry_budget_policy
                .map(|policy| Arc::new(RetryBudget::new(policy, Arc::clone(&clock)))),
            circuit_breaker: self
                .circuit_breaker_policy
                .map(|policy| Arc::new(CircuitBreaker::new(policy, Arc::clone(&clock)))),
            adaptive_concurrency: self.adaptive_concurrency_policy.map(|policy| {
                Arc::new(AdaptiveConcurrencyController::new(
                    policy,
                    Arc::clone(&clock),
                ))
            }),
            rate_limiter: RateLimiter::new(
                self.global_rate_limit_policy,
                self.per_host_rate_limit_policy,
                Arc::clone(&clock),
            )
            .map(Arc::new),
            server_throttle_scope: self.server_throttle_scope,
            redirect_policy: self.redirect_policy,
            default_status_policy: self.default_status_policy,
            client_name: self.client_name,
            tls_backend: self.tls_backend,
            proxy_config,
            transport,
            endpoint_selector: self.endpoint_selector,
            body_codec: self.body_codec,
            clock: Arc::clone(&clock),
            backoff_source: self.backoff_source,
            request_limiters: RequestLimiters::new(
                self.max_in_flight,
                self.max_in_flight_per_host,
                Arc::clone(&clock),
            ),
            metrics: ClientMetrics::with_options(self.metrics_enabled, otel),
            interceptors: self.interceptors,
            observers: self.observers,
        })
    }
}

#[derive(Clone)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs",
        feature = "async-tls-native"
    )))
)]
/// Reusable async HTTP client for SDK transports.
pub struct Client {
    base_url: String,
    default_headers: HeaderMap,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    stream_deadline_slack: Duration,
    max_response_body_bytes: usize,
    retry_policy: RetryPolicy,
    retry_eligibility: Arc<dyn RetryEligibility>,
    retry_budget: Option<Arc<RetryBudget>>,
    circuit_breaker: Option<Arc<CircuitBreaker>>,
    adaptive_concurrency: Option<Arc<AdaptiveConcurrencyController>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    server_throttle_scope: ServerThrottleScope,
    redirect_policy: RedirectPolicy,
    default_status_policy: StatusPolicy,
    client_name: String,
    tls_backend: TlsBackend,
    proxy_config: Option<ProxyConfig>,
    transport: TransportClient,
    endpoint_selector: Arc<dyn EndpointSelector>,
    body_codec: Arc<dyn BodyCodec>,
    clock: Arc<dyn Clock>,
    backoff_source: Arc<dyn BackoffSource>,
    request_limiters: Option<RequestLimiters>,
    metrics: ClientMetrics,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}

impl Client {
    /// Starts building a client for requests rooted at `base_url`.
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    /// Starts building a request with an explicit HTTP method.
    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, path.into())
    }

    /// Starts a `GET` request.
    pub fn get(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::GET, path)
    }

    /// Starts a `POST` request.
    pub fn post(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::POST, path)
    }

    /// Starts a `PUT` request.
    pub fn put(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PUT, path)
    }

    /// Starts a `PATCH` request.
    pub fn patch(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PATCH, path)
    }

    /// Starts a `DELETE` request.
    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::DELETE, path)
    }

    /// Returns the current client metrics snapshot.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Returns the TLS backend chosen for this client.
    pub fn tls_backend(&self) -> TlsBackend {
        self.tls_backend
    }

    /// Returns the default status policy applied to requests.
    pub fn default_status_policy(&self) -> StatusPolicy {
        self.default_status_policy
    }

    fn run_request_interceptors(&self, context: &RequestContext, headers: &mut HeaderMap) {
        for interceptor in &self.interceptors {
            interceptor.on_request(context, headers);
        }
    }

    fn should_apply_http_proxy_auth_header(&self, uri: &Uri) -> bool {
        let Some(proxy_config) = &self.proxy_config else {
            return false;
        };
        let Some(scheme) = uri.scheme_str() else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("http") {
            return false;
        }
        !should_bypass_proxy_uri(&proxy_config.no_proxy_rules, uri)
    }

    fn apply_http_proxy_auth_header(&self, uri: &Uri, headers: &mut HeaderMap) {
        if !self.should_apply_http_proxy_auth_header(uri)
            || headers.contains_key(PROXY_AUTHORIZATION)
        {
            return;
        }
        if let Some(proxy_config) = &self.proxy_config
            && let Some(proxy_authorization) = &proxy_config.authorization
        {
            headers.insert(PROXY_AUTHORIZATION, proxy_authorization.clone());
        }
    }

    fn run_response_interceptors(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
    ) {
        for interceptor in &self.interceptors {
            interceptor.on_response(context, status, headers);
        }
    }

    fn run_error_interceptors(&self, context: &RequestContext, error: &Error) {
        for interceptor in &self.interceptors {
            interceptor.on_error(context, error);
        }
    }

    fn run_request_start_observers(&self, context: &RequestContext) {
        for observer in &self.observers {
            observer.on_request_start(context);
        }
    }

    fn run_retry_observers(
        &self,
        context: &RequestContext,
        decision: &RetryDecision,
        delay: Duration,
    ) {
        for observer in &self.observers {
            observer.on_retry_scheduled(context, decision, delay);
        }
    }

    fn run_server_throttle_observers(
        &self,
        context: &RequestContext,
        scope: ServerThrottleScope,
        delay: Duration,
    ) {
        for observer in &self.observers {
            observer.on_server_throttle(context, scope, delay);
        }
    }

    fn stream_response(&self, input: StreamResponseBuildInput<'_>) -> RetryResponse {
        let StreamResponseBuildInput {
            status,
            response_headers,
            response_body,
            execution,
            transport_timeout,
            stream_total_timeout_ms,
            stream_deadline_at,
            stream_lifecycle,
            stream_global_permit,
            host_permit,
        } = input;
        stream_retry_response(StreamResponseInput {
            status,
            response_headers,
            response_body,
            method: execution.current_method().clone(),
            uri: execution.current_uri().clone(),
            redacted_uri: execution.current_redacted_uri().to_owned(),
            transport_timeout,
            stream_total_timeout_ms,
            stream_deadline_at,
            stream_deadline_slack: self.stream_deadline_slack,
            stream_lifecycle,
            stream_global_permit: stream_global_permit.take(),
            host_permit,
        })
    }

    fn try_consume_retry_budget(&self, method: &Method, uri: &str) -> Result<(), Error> {
        let Some(retry_budget) = &self.retry_budget else {
            return Ok(());
        };
        if retry_budget.try_consume_retry() {
            Ok(())
        } else {
            Err(Error::RetryBudgetExhausted {
                method: method.clone(),
                uri: uri.to_owned(),
            })
        }
    }

    fn begin_circuit_attempt(
        &self,
        method: &Method,
        uri: &str,
    ) -> Result<Option<crate::resilience::CircuitAttempt>, Error> {
        let Some(circuit_breaker) = &self.circuit_breaker else {
            return Ok(None);
        };

        match circuit_breaker.begin() {
            Ok(attempt) => Ok(Some(attempt)),
            Err(retry_after) => Err(Error::CircuitOpen {
                method: method.clone(),
                uri: uri.to_owned(),
                retry_after_ms: retry_after.as_millis(),
            }),
        }
    }

    async fn begin_adaptive_attempt(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<AdaptiveConcurrencyPermit>, Error> {
        let Some(controller) = self.adaptive_concurrency.as_ref() else {
            return Ok(None);
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return Ok(Some(controller.acquire().await));
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            controller.acquire(),
        )
        .await
        {
            Ok(permit) => Ok(Some(permit)),
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn acquire_rate_limit_slot(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<(), Error> {
        let Some(rate_limiter) = &self.rate_limiter else {
            return Ok(());
        };

        loop {
            let wait = rate_limiter.acquire_delay(host);
            if wait.is_zero() {
                return Ok(());
            }
            let Some(wait) = bounded_retry_delay(wait, total_timeout, request_started_at) else {
                return Err(deadline_exceeded_error(total_timeout, method, uri));
            };
            sleep(wait).await;
        }
    }

    fn observe_server_throttle(
        &self,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
        host: Option<&str>,
        fallback_delay: Duration,
    ) {
        if status != http::StatusCode::TOO_MANY_REQUESTS {
            return;
        }
        let throttle_delay = server_throttle_delay(self.clock.as_ref(), headers, fallback_delay);
        let header_scope_hint = server_throttle_scope_from_headers(headers);
        let resolved_scope = match &self.rate_limiter {
            Some(rate_limiter) => rate_limiter.observe_server_throttle(
                host,
                throttle_delay,
                self.server_throttle_scope,
                header_scope_hint,
            ),
            None => resolve_server_throttle_scope(
                self.server_throttle_scope,
                header_scope_hint,
                host.is_some(),
                false,
                false,
            ),
        };
        self.run_server_throttle_observers(context, resolved_scope, throttle_delay);
    }

    fn decode_response_body_limited(
        &self,
        body: Bytes,
        headers: &HeaderMap,
        max_response_body_bytes: usize,
        status: http::StatusCode,
        context: &RequestContext,
    ) -> Result<Bytes, Error> {
        let method = context.method();
        let redacted_uri = context.uri();
        if !should_decode_content_encoded_body(method, status, body.len()) {
            return Ok(body);
        }
        self.body_codec
            .decode_response_body_limited(
                body,
                headers,
                max_response_body_bytes,
                method,
                redacted_uri,
            )
            .inspect_err(|error| self.run_error_interceptors(context, error))
    }

    fn prepare_retry(
        &self,
        retry_attempt: RetryAttemptState<'_>,
        context: &RequestContext,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
        error: &Error,
    ) -> Result<RetrySchedule, Error> {
        let retry_schedule = match retry_attempt.prepare_retry_schedule(
            retry_decision,
            requested_delay,
            |method, uri| self.try_consume_retry_budget(method, uri),
        ) {
            Ok(schedule) => schedule,
            Err(error) => {
                self.run_error_interceptors(context, &error);
                return Err(error);
            }
        };
        let RetrySchedule::Scheduled { delay: retry_delay } = retry_schedule else {
            return Ok(RetrySchedule::NotScheduled);
        };

        let delay_ms = duration_millis_u64_saturating(retry_delay);
        match retry_decision.reason() {
            RetryReason::Status(status) => {
                warn!(
                    status = status.as_u16(),
                    delay_ms,
                    error = %error,
                    "retrying request after retryable status"
                );
            }
            RetryReason::ResponseBodyRead => {
                warn!(
                    delay_ms,
                    error = %error,
                    "retrying request after response body read error"
                );
            }
            RetryReason::Timeout(_) => {
                warn!(delay_ms, error = %error, "retrying request after timeout");
            }
            RetryReason::Transport(_) => {
                warn!(delay_ms, error = %error, "retrying request after transport error");
            }
        }

        self.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        Ok(RetrySchedule::Scheduled { delay: retry_delay })
    }

    fn prepare_status_retry(
        &self,
        state: &mut RequestExecutionState,
        context: &RequestContext,
        status: http::StatusCode,
        headers: &HeaderMap,
    ) -> Result<RetrySchedule, Error> {
        let retry_plan = state.status_retry_plan(
            status,
            headers,
            self.clock.as_ref(),
            self.backoff_source.as_ref(),
        );
        let retry_error = state.status_retry_error(status, headers);
        self.prepare_retry(
            state.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
            &retry_error,
        )
    }

    fn handle_body_read_failure(
        &self,
        read_context: &mut BodyReadRetryContext<'_>,
        failure: BodyReadFailure,
    ) -> Result<BodyReadOutcome, Error> {
        let (error, retry_plan) = match failure {
            BodyReadFailure::Terminal { error } => {
                self.run_error_interceptors(read_context.context(), &error);
                return Err(error);
            }
            BodyReadFailure::Retryable { error, retry_plan } => (error, retry_plan),
        };

        let context = read_context.context();
        match self.prepare_retry(
            read_context.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
            &error,
        )? {
            RetrySchedule::Scheduled { delay } => return Ok(BodyReadOutcome::Retry(delay)),
            RetrySchedule::NotScheduled => {}
        }
        self.run_error_interceptors(context, &error);
        Err(error)
    }

    async fn read_response_body_with_retry(
        &self,
        body: Incoming,
        mut read_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        match timeout(
            read_context.read_timeout(),
            read_all_body_limited(body, read_context.max_response_body_bytes()),
        )
        .await
        {
            Ok(Ok(body)) => Ok(BodyReadOutcome::Body(body)),
            Ok(Err(ReadBodyError::Read(source))) => {
                let failure =
                    read_context.response_body_read_failure(source, self.backoff_source.as_ref());
                self.handle_body_read_failure(&mut read_context, failure)
            }
            Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                let error = read_context.response_body_too_large_error(actual_bytes);
                self.run_error_interceptors(read_context.context(), &error);
                Err(error)
            }
            Err(_) => {
                let failure =
                    read_context.response_body_timeout_failure(self.backoff_source.as_ref());
                self.handle_body_read_failure(&mut read_context, failure)
            }
        }
    }

    async fn read_decoded_response_body_with_retry(
        &self,
        body: Incoming,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        read_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        let max_response_body_bytes = read_context.max_response_body_bytes();
        let context = read_context.context();
        let deadline = read_context.deadline();
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let response_body = match self
            .read_response_body_with_retry(body, read_context)
            .await?
        {
            BodyReadOutcome::Body(body) => body,
            BodyReadOutcome::Retry(delay) => return Ok(BodyReadOutcome::Retry(delay)),
        };
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let should_decode_response_body =
            should_decode_content_encoded_body(context.method(), status, response_body.len());
        let response_body = self.decode_response_body_limited(
            response_body,
            response_headers,
            max_response_body_bytes,
            status,
            context,
        )?;
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        if should_decode_response_body && response_headers.contains_key(CONTENT_ENCODING) {
            remove_content_encoding_headers(response_headers);
        }
        Ok(BodyReadOutcome::Body(response_body))
    }

    async fn acquire_global_request_permit(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<GlobalRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(GlobalRequestPermit { _permit: None });
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return limiters.acquire_global().await;
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            limiters.acquire_global(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn acquire_host_request_permit(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<HostRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(HostRequestPermit { _permit: None });
        };
        let Some(deadline_at) = total_timeout_deadline(total_timeout, request_started_at) else {
            return limiters.acquire_host(host).await;
        };
        if Instant::now() >= deadline_at {
            return Err(deadline_exceeded_error(total_timeout, method, uri));
        }

        match timeout_at(
            tokio::time::Instant::from_std(deadline_at),
            limiters.acquire_host(host),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    async fn send_transport_request(
        &self,
        transport_timeout: Duration,
        request: Request<ReqBody>,
    ) -> Result<HttpResponse<Incoming>, TransportRequestError> {
        match timeout(transport_timeout, self.transport.request(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(source)) => Err(TransportRequestError::Transport(source)),
            Err(_) => Err(TransportRequestError::Timeout),
        }
    }

    pub(crate) async fn send_request(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOptions,
    ) -> Result<Response, Error> {
        let request_input = prepare_retry_request_input(
            RequestExecutionPreparation {
                endpoint_selector: self.endpoint_selector.as_ref(),
                configured_base_url: &self.base_url,
                method,
                path,
                default_headers: &self.default_headers,
                headers,
                body,
                execution_options,
                defaults: RequestExecutionDefaults {
                    request_timeout: self.request_timeout,
                    total_timeout: self.total_timeout,
                    retry_policy: &self.retry_policy,
                    max_response_body_bytes: self.max_response_body_bytes,
                    redirect_policy: self.redirect_policy,
                    status_policy: self.default_status_policy,
                    auto_accept_encoding: self.buffered_auto_accept_encoding,
                },
            },
            RequestBody::empty,
            ensure_accept_encoding_async,
        )?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, false);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let _global_permit = match self
            .acquire_global_request_permit(
                total_timeout,
                request_started_at,
                &method,
                &redacted_uri_text,
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                self.metrics
                    .finish_otel_request_span_error(otel_span, &error);
                return Err(error);
            }
        };

        let result = self
            .send_request_with_retry(request_input, request_started_at)
            .await;
        self.metrics
            .record_request_completed(&result, request_started_at.elapsed());
        match &result {
            Ok(response) => self
                .metrics
                .finish_otel_request_span_success(otel_span, response.status().as_u16()),
            Err(error) => self
                .metrics
                .finish_otel_request_span_error(otel_span, error),
        }
        result
    }

    pub(crate) async fn send_request_stream(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOptions,
    ) -> Result<ResponseStream, Error> {
        let request_input = prepare_retry_request_input(
            RequestExecutionPreparation {
                endpoint_selector: self.endpoint_selector.as_ref(),
                configured_base_url: &self.base_url,
                method,
                path,
                default_headers: &self.default_headers,
                headers,
                body,
                execution_options,
                defaults: RequestExecutionDefaults {
                    request_timeout: self.request_timeout,
                    total_timeout: self.total_timeout,
                    retry_policy: &self.retry_policy,
                    max_response_body_bytes: self.max_response_body_bytes,
                    redirect_policy: self.redirect_policy,
                    status_policy: self.default_status_policy,
                    auto_accept_encoding: self.stream_auto_accept_encoding,
                },
            },
            RequestBody::empty,
            ensure_accept_encoding_async,
        )?;
        let redacted_uri_text = request_input.redacted_uri_text.clone();
        let method = request_input.method.clone();
        let total_timeout = request_input.execution_options.total_timeout;
        let mut otel_span = Some(self.metrics.start_otel_request_span(
            &method,
            &redacted_uri_text,
            true,
        ));
        self.metrics.record_request_started();
        let in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let global_permit = match self
            .acquire_global_request_permit(
                total_timeout,
                request_started_at,
                &method,
                &redacted_uri_text,
            )
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                return Err(error);
            }
        };
        let expected_method = method.clone();
        let expected_redacted_uri = redacted_uri_text.clone();

        match self
            .send_request_with_retry_mode(
                request_input,
                ResponseMode::Stream,
                Some(global_permit),
                request_started_at,
            )
            .await
        {
            Ok(RetryResponse::Stream(response)) => {
                let mut response = *response;
                let completion = self.metrics.stream_completion(
                    otel_span.take(),
                    request_started_at,
                    response.status().as_u16(),
                    in_flight,
                );
                response.attach_completion(completion);
                Ok(response)
            }
            Ok(RetryResponse::Buffered(_)) => {
                let error = response_mode_mismatch_error(
                    &expected_method,
                    &expected_redacted_uri,
                    "stream",
                );
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                Err(error)
            }
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                if let Some(otel_span) = otel_span.take() {
                    self.metrics
                        .finish_otel_request_span_error(otel_span, &error);
                }
                Err(error)
            }
        }
    }

    async fn send_request_with_retry(
        &self,
        input: RetryRequestInput<RequestBody>,
        request_started_at: Instant,
    ) -> Result<Response, Error> {
        let expected_method = input.method.clone();
        let expected_redacted_uri = input.redacted_uri_text.clone();
        match self
            .send_request_with_retry_mode(input, ResponseMode::Buffered, None, request_started_at)
            .await?
        {
            RetryResponse::Buffered(response) => Ok(response),
            RetryResponse::Stream(_) => Err(response_mode_mismatch_error(
                &expected_method,
                &expected_redacted_uri,
                "buffered",
            )),
        }
    }

    async fn send_request_with_retry_mode(
        &self,
        input: RetryRequestInput<RequestBody>,
        response_mode: ResponseMode,
        stream_global_permit: Option<GlobalRequestPermit>,
        request_started_at: Instant,
    ) -> Result<RetryResponse, Error> {
        let RetryRequestInput {
            method,
            uri,
            redacted_uri_text,
            merged_headers,
            body,
            execution_options,
        } = input;
        let timeout_value = execution_options.request_timeout;
        let total_timeout = execution_options.total_timeout;
        let max_response_body_bytes = execution_options.max_response_body_bytes;
        let (mut buffered_body, mut streaming_body) = match body {
            RequestBody::Buffered(body) => (Some(body), None),
            RequestBody::Streaming(body) => (None, Some(body)),
        };
        let body_replayable = buffered_body.is_some();
        let retry_policy = execution_options.retry_policy;
        let redirect_policy = execution_options.redirect_policy;
        let status_policy = execution_options.status_policy;
        let mut execution = RequestExecutionState::new(
            RequestExecutionStateInput {
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body_replayable,
                retry_policy,
                redirect_policy,
                status_policy,
                timeout_value,
                total_timeout,
                max_response_body_bytes,
                request_started_at,
            },
            self.retry_eligibility.as_ref(),
        );

        let stream_timing = execution.stream_timing();
        let stream_total_timeout_ms = stream_timing.total_timeout_ms;
        let stream_deadline_at = stream_timing.deadline_at;
        let mut stream_global_permit = stream_global_permit;

        while execution.can_attempt() {
            let span = if response_mode.is_stream() {
                info_span!(
                    "reqx.request.stream",
                    client = %self.client_name,
                    method = %execution.current_method(),
                    uri = %execution.current_redacted_uri(),
                    attempt = execution.attempt(),
                    max_attempts = execution.max_attempts()
                )
            } else {
                info_span!(
                    "reqx.request",
                    client = %self.client_name,
                    method = %execution.current_method(),
                    uri = %execution.current_redacted_uri(),
                    attempt = execution.attempt(),
                    max_attempts = execution.max_attempts()
                )
            };
            let started = Instant::now();
            let context = execution.context();
            span.in_scope(|| self.run_request_start_observers(&context));
            debug!(parent: &span, "sending request");
            let rate_limit_host = execution.rate_limit_host();
            if let Err(error) = self
                .acquire_rate_limit_slot(
                    rate_limit_host.as_deref(),
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            let host_permit = match self
                .acquire_host_request_permit(
                    rate_limit_host.as_deref(),
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
                Ok(permit) => permit,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let circuit_attempt = match self
                .begin_circuit_attempt(execution.current_method(), execution.current_redacted_uri())
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let mut attempts: AttemptGuards<
                crate::resilience::CircuitAttempt,
                AdaptiveConcurrencyPermit,
            > = AttemptGuards::new(circuit_attempt, None);
            let adaptive_attempt = match self
                .begin_adaptive_attempt(
                    execution.total_timeout(),
                    execution.request_started_at(),
                    execution.current_method(),
                    execution.current_redacted_uri(),
                )
                .instrument(span.clone())
                .await
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    attempts.cancel();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            attempts.set_adaptive(adaptive_attempt);
            let mut attempt_headers = execution.current_headers().clone();
            self.run_request_interceptors(&context, &mut attempt_headers);
            // Never forward hop-by-hop proxy credentials to origin servers.
            attempt_headers.remove(PROXY_AUTHORIZATION);
            self.apply_http_proxy_auth_header(execution.current_uri(), &mut attempt_headers);
            let Some(transport_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };
            let request_body = if let Some(body) = &buffered_body {
                buffered_req_body(body.clone())
            } else {
                streaming_body.take().unwrap_or_else(empty_req_body)
            };
            let request = build_http_request(
                execution.current_method().clone(),
                execution.current_uri().clone(),
                &attempt_headers,
                request_body,
            );
            let request = match request {
                Ok(request) => request,
                Err(error) => {
                    attempts.cancel();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let response = match self
                .send_transport_request(transport_timeout, request)
                .instrument(span.clone())
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let error = error.into_error(&execution, transport_timeout);
                    match execution.transport_failure_plan(&error, self.backoff_source.as_ref()) {
                        TransportFailurePlan::Retry(retry_plan) => {
                            match attempts.record_failure_for_retry_schedule(self.prepare_retry(
                                execution.retry_attempt(),
                                &context,
                                &retry_plan.decision,
                                retry_plan.delay,
                                &error,
                            ))? {
                                RetrySchedule::Scheduled { delay: retry_delay } => {
                                    drop(host_permit);
                                    if !retry_delay.is_zero() {
                                        sleep(retry_delay).instrument(span.clone()).await;
                                    }
                                    continue;
                                }
                                RetrySchedule::NotScheduled => {
                                    attempts.mark_failure();
                                }
                            }
                        }
                        TransportFailurePlan::Terminal {
                            attempt_disposition,
                        } => {
                            attempt_disposition.apply(&mut attempts);
                        }
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            let status = response.status();
            let mut response_headers = response.headers().clone();
            let redirect_action = match execution.next_redirect_action(status, &response_headers) {
                Ok(action) => action,
                Err(error) => {
                    attempts.mark_failure();
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            if let Some(redirect_action) = redirect_action {
                self.run_response_interceptors(&context, status, &response_headers);
                attempts.mark_success();
                let drops_body =
                    execution.apply_redirect(redirect_action, self.retry_eligibility.as_ref());
                if drops_body {
                    buffered_body = None;
                    streaming_body = None;
                }
                continue;
            }

            let mut response_progress = ResponseProgress::default();

            if response_mode.is_stream() {
                response_progress.run_response_interceptors_if_needed(|| {
                    self.run_response_interceptors(&context, status, &response_headers);
                });

                if status.is_success() {
                    let stream_lifecycle = RequestCompletion::success()
                        .into_stream_lifecycle(&mut attempts, self.retry_budget.clone());
                    return Ok(self.stream_response(StreamResponseBuildInput {
                        status,
                        response_headers,
                        response_body: response.into_body(),
                        execution: &execution,
                        transport_timeout,
                        stream_total_timeout_ms,
                        stream_deadline_at,
                        stream_lifecycle,
                        stream_global_permit: &mut stream_global_permit,
                        host_permit,
                    }));
                }
            }

            if !status.is_success() {
                let server_throttle_fallback_delay =
                    execution.retry_backoff(self.backoff_source.as_ref());
                match attempts.record_failure_for_retry_schedule(
                    response_progress.prepare_non_success_before_body(
                        || self.run_response_interceptors(&context, status, &response_headers),
                        || {
                            self.observe_server_throttle(
                                &context,
                                status,
                                &response_headers,
                                rate_limit_host.as_deref(),
                                server_throttle_fallback_delay,
                            );
                        },
                        || {
                            self.prepare_status_retry(
                                &mut execution,
                                &context,
                                status,
                                &response_headers,
                            )
                        },
                    ),
                )? {
                    RetrySchedule::Scheduled { delay: retry_delay } => {
                        drop(response);
                        drop(host_permit);
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).instrument(span.clone()).await;
                        }
                        continue;
                    }
                    RetrySchedule::NotScheduled => {
                        // Keep the attempt open so terminal non-success handling can record the
                        // correct success/failure disposition.
                    }
                }
                if response_mode.is_stream() && execution.should_return_non_success_response() {
                    let stream_lifecycle = execution
                        .non_success_completion(status)
                        .into_stream_lifecycle(&mut attempts, self.retry_budget.clone());
                    return Ok(self.stream_response(StreamResponseBuildInput {
                        status,
                        response_headers,
                        response_body: response.into_body(),
                        execution: &execution,
                        transport_timeout,
                        stream_total_timeout_ms,
                        stream_deadline_at,
                        stream_lifecycle,
                        stream_global_permit: &mut stream_global_permit,
                        host_permit,
                    }));
                }
            }

            let Some(read_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.mark_failure();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };

            let response_body = match attempts.record_failure_on_error(
                self.read_decoded_response_body_with_retry(
                    response.into_body(),
                    &mut response_headers,
                    status,
                    execution.body_read_retry_context(&context, read_timeout),
                )
                .instrument(span.clone())
                .await,
            )? {
                BodyReadOutcome::Body(body) => body,
                BodyReadOutcome::Retry(retry_delay) => {
                    attempts.mark_failure();
                    drop(host_permit);
                    if !retry_delay.is_zero() {
                        sleep(retry_delay).instrument(span.clone()).await;
                    }
                    continue;
                }
            };

            if response_mode.is_buffered() {
                debug!(
                    parent: &span,
                    status = status.as_u16(),
                    elapsed_ms = duration_millis_u64_saturating(started.elapsed()),
                    "request completed"
                );
            }
            response_progress.run_response_interceptors_if_needed(|| {
                self.run_response_interceptors(&context, status, &response_headers);
            });

            if !status.is_success() {
                if execution.should_return_non_success_response() && response_mode.is_buffered() {
                    let completion = execution.non_success_completion(status);
                    completion.record_completed(&mut attempts, self.retry_budget.as_ref());
                    return Ok(RetryResponse::Buffered(Response::new(
                        status,
                        response_headers,
                        response_body,
                    )));
                }

                let terminal =
                    execution.terminal_non_success(status, &response_headers, &response_body);
                terminal
                    .completion
                    .record_completed(&mut attempts, self.retry_budget.as_ref());
                self.run_error_interceptors(&context, &terminal.error);
                return Err(terminal.error);
            }

            RequestCompletion::success()
                .record_completed(&mut attempts, self.retry_budget.as_ref());
            return Ok(RetryResponse::Buffered(Response::new(
                status,
                response_headers,
                response_body,
            )));
        }

        let error = execution.deadline_error();
        let context = execution.context();
        self.run_error_interceptors(&context, &error);
        Err(error)
    }
}
