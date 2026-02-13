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
use tracing::{debug, info_span, warn};

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_rustls::HttpsConnectorBuilder;

use crate::body::{
    ReadBodyError, ReqBody, RequestBody, buffered_req_body, build_http_request, empty_req_body,
    read_all_body_limited,
};
use crate::config::{AdvancedConfig, ClientProfile};
use crate::content_encoding::should_decode_content_encoded_body;
use crate::error::{Error, TimeoutPhase, TransportErrorKind};
use crate::execution::{
    RedirectInput, RedirectTransitionInput, StatusRetryPlanInput, apply_redirect_transition,
    effective_status_policy, http_status_error, next_redirect_action,
    response_body_read_retry_decision, select_base_url, should_mark_non_success_for_resilience,
    should_return_non_success_response, status_retry_delay, status_retry_error, status_retry_plan,
    timeout_retry_decision, transport_retry_decision_from_error, transport_timeout_error,
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
    NoProxyRule, ProxyConfig, parse_no_proxy_rule, parse_no_proxy_rules, should_bypass_proxy_uri,
};
use crate::rate_limit::{
    RateLimitPolicy, RateLimiter, ServerThrottleScope, server_throttle_scope_from_headers,
};
use crate::request::RequestBuilder;
use crate::resilience::{
    AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState, CircuitBreaker, CircuitBreakerPolicy,
    RetryBudget, RetryBudgetPolicy,
};
use crate::response::{Response, ResponseStream, ResponseStreamContext, StreamPermits};
use crate::retry::{
    PermissiveRetryEligibility, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "async-tls-native"
))]
use crate::tls::tls_config_error;
use crate::tls::{TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore};
use crate::util::{
    bounded_retry_delay, classify_transport_error, deadline_exceeded_error,
    ensure_accept_encoding_async, lock_unpoisoned, merge_headers, parse_header_name,
    parse_header_value, phase_timeout, rate_limit_bucket_key, redact_uri_for_logs, resolve_uri,
    total_timeout_deadline, total_timeout_expired, truncate_body, validate_base_url,
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
            TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            tls_backend,
            "custom root CAs require tls_root_store(TlsRootStore::System) or tls_root_store(TlsRootStore::Specific)",
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
        TlsRootStore::System | TlsRootStore::Specific
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
fn build_rustls_tls_config(
    tls_backend: TlsBackend,
    provider: impl Into<Arc<rustls::crypto::CryptoProvider>>,
    tls_options: &TlsOptions,
) -> crate::Result<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;

    let root_store = build_rustls_root_store(tls_backend, tls_options)?;

    let config_builder = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
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

struct RetryContext<'a> {
    context: &'a RequestContext,
    retry_policy: &'a RetryPolicy,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    method: &'a Method,
    redacted_uri: &'a str,
    max_attempts: usize,
}

struct ReadBodyRetryContext<'a> {
    context: &'a RequestContext,
    max_response_body_bytes: usize,
    timeout_value: Duration,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    method: &'a Method,
    redacted_uri: &'a str,
    retry_policy: &'a RetryPolicy,
    max_attempts: usize,
    attempt: &'a mut usize,
}

struct StatusRetryContext<'a> {
    context: &'a RequestContext,
    retry_policy: &'a RetryPolicy,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    method: &'a Method,
    redacted_uri: &'a str,
    status: http::StatusCode,
    headers: &'a HeaderMap,
    max_attempts: usize,
}

struct RetryRequestInput {
    method: Method,
    uri: Uri,
    redacted_uri_text: String,
    merged_headers: HeaderMap,
    body: RequestBody,
    execution_options: RequestExecutionOptions,
}

#[derive(Clone, Copy)]
enum ResponseMode {
    Buffered,
    Stream,
}

enum RetryResponse {
    Buffered(Response),
    Stream(ResponseStream),
}

fn response_mode_mismatch_error(method: &Method, redacted_uri: &str, expected_mode: &str) -> Error {
    Error::Transport {
        kind: TransportErrorKind::Other,
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        source: Box::new(std::io::Error::other(format!(
            "internal response mode mismatch: expected {expected_mode} response variant"
        ))),
    }
}

fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
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
fn build_native_tls_connector(
    tls_options: &TlsOptions,
) -> crate::Result<hyper_tls::native_tls::TlsConnector> {
    let mut connector_builder = hyper_tls::native_tls::TlsConnector::builder();

    if !tls_options.root_certificates.is_empty()
        && !matches!(
            tls_options.root_store,
            TlsRootStore::System | TlsRootStore::Specific
        )
    {
        return Err(tls_config_error(
            TlsBackend::NativeTls,
            "custom root CAs require tls_root_store(TlsRootStore::System) or tls_root_store(TlsRootStore::Specific)",
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

#[derive(Debug)]
struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    notify: Notify,
}

impl AdaptiveConcurrencyController {
    fn new(policy: AdaptiveConcurrencyPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState::new(policy)),
            notify: Notify::new(),
        }
    }

    async fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        loop {
            {
                let mut state = lock_unpoisoned(&self.state);
                if state.try_acquire() {
                    return AdaptiveConcurrencyPermit {
                        controller: Arc::clone(self),
                        started_at: Instant::now(),
                        completed: false,
                    };
                }
            }
            self.notify.notified().await;
        }
    }

    fn release_and_record(&self, success: bool, latency: Duration) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_and_record(self.policy, success, latency);
        self.notify.notify_waiters();
    }
}

struct AdaptiveConcurrencyPermit {
    controller: Arc<AdaptiveConcurrencyController>,
    started_at: Instant,
    completed: bool,
}

impl AdaptiveConcurrencyPermit {
    fn mark_success(mut self) {
        self.controller
            .release_and_record(true, self.started_at.elapsed());
        self.completed = true;
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        if !self.completed {
            self.controller
                .release_and_record(false, self.started_at.elapsed());
            self.completed = true;
        }
    }
}

pub(crate) struct RequestExecutionOptions {
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) max_response_body_bytes: Option<usize>,
    pub(crate) redirect_policy: Option<RedirectPolicy>,
    pub(crate) status_policy: Option<StatusPolicy>,
    pub(crate) auto_accept_encoding: Option<bool>,
}

pub struct ClientBuilder {
    base_url: String,
    default_headers: HeaderMap,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
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

    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout.max(Duration::from_millis(1));
        self
    }

    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = max_response_body_bytes.max(1);
        self
    }

    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout.max(Duration::from_millis(1));
        self
    }

    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.pool_idle_timeout = pool_idle_timeout.max(Duration::from_millis(1));
        self
    }

    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.pool_max_idle_per_host = pool_max_idle_per_host.max(1);
        self
    }

    pub fn http2_only(mut self, http2_only: bool) -> Self {
        self.http2_only = http2_only;
        self
    }

    pub fn http_proxy(mut self, proxy_uri: Uri) -> Self {
        self.http_proxy = Some(proxy_uri);
        self
    }

    pub fn proxy_authorization(mut self, mut proxy_authorization: HeaderValue) -> Self {
        proxy_authorization.set_sensitive(true);
        self.proxy_authorization = Some(proxy_authorization);
        self
    }

    pub fn try_proxy_authorization(self, proxy_authorization: &str) -> crate::Result<Self> {
        let proxy_authorization = parse_header_value("proxy-authorization", proxy_authorization)?;
        Ok(self.proxy_authorization(proxy_authorization))
    }

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
                None => self.invalid_no_proxy_rules.push(raw.to_owned()),
            }
        }
        self
    }

    pub fn try_no_proxy<I, S>(mut self, rules: I) -> crate::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.no_proxy_rules = parse_no_proxy_rules(rules)?;
        self.invalid_no_proxy_rules.clear();
        Ok(self)
    }

    pub fn add_no_proxy(mut self, rule: impl AsRef<str>) -> Self {
        let raw = rule.as_ref();
        if let Some(rule) = NoProxyRule::parse(raw) {
            self.no_proxy_rules.push(rule);
        } else {
            self.invalid_no_proxy_rules.push(raw.to_owned());
        }
        self
    }

    pub fn try_add_no_proxy(mut self, rule: impl AsRef<str>) -> crate::Result<Self> {
        self.no_proxy_rules
            .push(parse_no_proxy_rule(rule.as_ref())?);
        Ok(self)
    }

    pub fn default_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.default_headers.insert(name, value);
        self
    }

    pub fn auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self.stream_auto_accept_encoding = enabled;
        self
    }

    pub fn buffered_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.buffered_auto_accept_encoding = enabled;
        self
    }

    pub fn stream_auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.stream_auto_accept_encoding = enabled;
        self
    }

    pub fn try_default_header(self, name: &str, value: &str) -> crate::Result<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.default_header(name, value))
    }

    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn retry_eligibility(mut self, retry_eligibility: Arc<dyn RetryEligibility>) -> Self {
        self.retry_eligibility = retry_eligibility;
        self
    }

    pub fn retry_budget_policy(mut self, retry_budget_policy: RetryBudgetPolicy) -> Self {
        self.retry_budget_policy = Some(retry_budget_policy);
        self
    }

    pub fn circuit_breaker_policy(mut self, circuit_breaker_policy: CircuitBreakerPolicy) -> Self {
        self.circuit_breaker_policy = Some(circuit_breaker_policy);
        self
    }

    pub fn adaptive_concurrency_policy(
        mut self,
        adaptive_concurrency_policy: AdaptiveConcurrencyPolicy,
    ) -> Self {
        self.adaptive_concurrency_policy = Some(adaptive_concurrency_policy);
        self
    }

    pub fn global_rate_limit_policy(mut self, global_rate_limit_policy: RateLimitPolicy) -> Self {
        self.global_rate_limit_policy = Some(global_rate_limit_policy);
        self
    }

    pub fn per_host_rate_limit_policy(
        mut self,
        per_host_rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        self.per_host_rate_limit_policy = Some(per_host_rate_limit_policy);
        self
    }

    pub fn server_throttle_scope(mut self, server_throttle_scope: ServerThrottleScope) -> Self {
        self.server_throttle_scope = server_throttle_scope;
        self
    }

    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    pub fn default_status_policy(mut self, default_status_policy: StatusPolicy) -> Self {
        self.default_status_policy = default_status_policy;
        self
    }

    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
        self
    }

    pub fn endpoint_selector_arc(mut self, endpoint_selector: Arc<dyn EndpointSelector>) -> Self {
        self.endpoint_selector = endpoint_selector;
        self
    }

    pub fn endpoint_selector<S>(self, endpoint_selector: S) -> Self
    where
        S: EndpointSelector + 'static,
    {
        self.endpoint_selector_arc(Arc::new(endpoint_selector))
    }

    pub fn body_codec_arc(mut self, body_codec: Arc<dyn BodyCodec>) -> Self {
        self.body_codec = body_codec;
        self
    }

    pub fn body_codec<C>(self, body_codec: C) -> Self
    where
        C: BodyCodec + 'static,
    {
        self.body_codec_arc(Arc::new(body_codec))
    }

    pub fn clock_arc(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn clock<C>(self, clock: C) -> Self
    where
        C: Clock + 'static,
    {
        self.clock_arc(Arc::new(clock))
    }

    pub fn backoff_source_arc(mut self, backoff_source: Arc<dyn BackoffSource>) -> Self {
        self.backoff_source = backoff_source;
        self
    }

    pub fn backoff_source<B>(self, backoff_source: B) -> Self
    where
        B: BackoffSource + 'static,
    {
        self.backoff_source_arc(Arc::new(backoff_source))
    }

    pub fn tls_root_store(mut self, tls_root_store: TlsRootStore) -> Self {
        self.tls_options.root_store = tls_root_store;
        self
    }

    pub fn tls_root_ca_pem(mut self, certificate_pem: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Pem(certificate_pem.into()));
        self
    }

    pub fn tls_root_ca_der(mut self, certificate_der: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Der(certificate_der.into()));
        self
    }

    pub fn clear_tls_root_cas(mut self) -> Self {
        self.tls_options.root_certificates.clear();
        self
    }

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

    pub fn clear_tls_client_identity(mut self) -> Self {
        self.tls_options.client_identity = None;
        self
    }

    pub fn allow_non_idempotent_retries(mut self, allow: bool) -> Self {
        self.retry_eligibility = if allow {
            Arc::new(PermissiveRetryEligibility)
        } else {
            Arc::new(StrictRetryEligibility)
        };
        self
    }

    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = client_name.into();
        self
    }

    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = Some(max_in_flight.max(1));
        self
    }

    pub fn max_in_flight_per_host(mut self, max_in_flight_per_host: usize) -> Self {
        self.max_in_flight_per_host = Some(max_in_flight_per_host.max(1));
        self
    }

    pub fn metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    pub fn otel_enabled(mut self, enabled: bool) -> Self {
        self.otel_enabled = enabled;
        self
    }

    pub fn otel_path_normalizer_arc(
        mut self,
        otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    ) -> Self {
        self.otel_path_normalizer = otel_path_normalizer;
        self
    }

    pub fn otel_path_normalizer<N>(self, otel_path_normalizer: N) -> Self
    where
        N: OtelPathNormalizer + 'static,
    {
        self.otel_path_normalizer_arc(Arc::new(otel_path_normalizer))
    }

    pub fn interceptor_arc(mut self, interceptor: Arc<dyn Interceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    pub fn interceptor<I>(self, interceptor: I) -> Self
    where
        I: Interceptor + 'static,
    {
        self.interceptor_arc(Arc::new(interceptor))
    }

    pub fn observer_arc(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observers.push(observer);
        self
    }

    pub fn observer<O>(self, observer: O) -> Self
    where
        O: Observer + 'static,
    {
        self.observer_arc(Arc::new(observer))
    }

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

    pub fn advanced(mut self, config: AdvancedConfig) -> Self {
        if let Some(request_timeout) = config.request_timeout {
            self.request_timeout = request_timeout.max(Duration::from_millis(1));
        }
        if let Some(total_timeout) = config.total_timeout {
            self.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        }
        if let Some(max_response_body_bytes) = config.max_response_body_bytes {
            self.max_response_body_bytes = max_response_body_bytes.max(1);
        }
        if let Some(connect_timeout) = config.connect_timeout {
            self.connect_timeout = connect_timeout.max(Duration::from_millis(1));
        }
        if let Some(redirect_policy) = config.redirect_policy {
            self.redirect_policy = redirect_policy;
        }
        if let Some(default_status_policy) = config.default_status_policy {
            self.default_status_policy = default_status_policy;
        }
        self
    }

    pub fn build(self) -> crate::Result<Client> {
        validate_base_url(&self.base_url)?;
        if let Some(rule) = self.invalid_no_proxy_rules.first() {
            return Err(Error::InvalidNoProxyRule { rule: rule.clone() });
        }
        if let Some(policy) = self.adaptive_concurrency_policy {
            policy.validate()?;
        }

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

        Ok(Client {
            base_url: self.base_url,
            default_headers: self.default_headers,
            buffered_auto_accept_encoding: self.buffered_auto_accept_encoding,
            stream_auto_accept_encoding: self.stream_auto_accept_encoding,
            request_timeout: self.request_timeout,
            total_timeout: self.total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
            retry_eligibility: self.retry_eligibility,
            retry_budget: self
                .retry_budget_policy
                .map(|policy| Arc::new(RetryBudget::new(policy))),
            circuit_breaker: self
                .circuit_breaker_policy
                .map(|policy| Arc::new(CircuitBreaker::new(policy))),
            adaptive_concurrency: self
                .adaptive_concurrency_policy
                .map(|policy| Arc::new(AdaptiveConcurrencyController::new(policy))),
            rate_limiter: RateLimiter::new(
                self.global_rate_limit_policy,
                self.per_host_rate_limit_policy,
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
            clock: self.clock,
            backoff_source: self.backoff_source,
            request_limiters: RequestLimiters::new(self.max_in_flight, self.max_in_flight_per_host),
            metrics: ClientMetrics::with_options(self.metrics_enabled, otel),
            interceptors: self.interceptors,
            observers: self.observers,
        })
    }
}

#[derive(Clone)]
pub struct Client {
    base_url: String,
    default_headers: HeaderMap,
    buffered_auto_accept_encoding: bool,
    stream_auto_accept_encoding: bool,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
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
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    pub fn request(&self, method: Method, path: impl Into<String>) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, path.into())
    }

    pub fn get(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::POST, path)
    }

    pub fn put(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PUT, path)
    }

    pub fn patch(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::PATCH, path)
    }

    pub fn delete(&self, path: impl Into<String>) -> RequestBuilder<'_> {
        self.request(Method::DELETE, path)
    }

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn tls_backend(&self) -> TlsBackend {
        self.tls_backend
    }

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

    fn run_server_throttle_observers(&self, context: &RequestContext, delay: Duration) {
        for observer in &self.observers {
            observer.on_server_throttle(context, self.server_throttle_scope, delay);
        }
    }

    fn record_successful_request_for_resilience(&self) {
        if let Some(retry_budget) = &self.retry_budget {
            retry_budget.record_success();
        }
    }

    fn maybe_record_terminal_response_success(
        &self,
        status: http::StatusCode,
        retry_policy: &RetryPolicy,
    ) {
        if !retry_policy.is_retryable_status(status) {
            self.record_successful_request_for_resilience();
        }
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
        let Some(rate_limiter) = &self.rate_limiter else {
            return;
        };
        let throttle_delay = status_retry_delay(self.clock.as_ref(), headers, fallback_delay);
        rate_limiter.observe_server_throttle(
            host,
            throttle_delay,
            self.server_throttle_scope,
            server_throttle_scope_from_headers(headers),
        );
        self.run_server_throttle_observers(context, throttle_delay);
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

    async fn schedule_retry(
        &self,
        retry_context: RetryContext<'_>,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
        attempt: &mut usize,
        error: &Error,
    ) -> Result<bool, Error> {
        let RetryContext {
            context,
            retry_policy,
            total_timeout,
            request_started_at,
            method,
            redacted_uri,
            max_attempts,
        } = retry_context;

        if *attempt >= max_attempts || !retry_policy.should_retry_decision(retry_decision) {
            return Ok(false);
        }

        if let Err(error) = self.try_consume_retry_budget(method, redacted_uri) {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let Some(retry_delay) =
            bounded_retry_delay(requested_delay, total_timeout, request_started_at)
        else {
            let error = deadline_exceeded_error(total_timeout, method, redacted_uri);
            self.run_error_interceptors(context, &error);
            return Err(error);
        };

        let delay_ms = retry_delay.as_millis() as u64;
        if let Some(status) = retry_decision.status {
            warn!(
                status = status.as_u16(),
                delay_ms,
                error = %error,
                "retrying request after retryable status"
            );
        } else if retry_decision.response_body_read_error {
            warn!(
                delay_ms,
                error = %error,
                "retrying request after response body read error"
            );
        } else if retry_decision.timeout_phase.is_some() {
            warn!(delay_ms, error = %error, "retrying request after timeout");
        } else if retry_decision.transport_error_kind.is_some() {
            warn!(delay_ms, error = %error, "retrying request after transport error");
        }

        self.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        if !retry_delay.is_zero() {
            sleep(retry_delay).await;
        }
        *attempt += 1;
        Ok(true)
    }

    async fn schedule_status_retry(
        &self,
        status_context: StatusRetryContext<'_>,
        attempt: &mut usize,
    ) -> Result<bool, Error> {
        let StatusRetryContext {
            context,
            retry_policy,
            total_timeout,
            request_started_at,
            method,
            redacted_uri,
            status,
            headers,
            max_attempts,
        } = status_context;
        let retry_plan = status_retry_plan(StatusRetryPlanInput {
            attempt: *attempt,
            max_attempts,
            method,
            redacted_uri,
            status,
            headers,
            clock: self.clock.as_ref(),
            fallback_delay: self
                .backoff_source
                .backoff_for_retry(retry_policy, *attempt),
        });
        let retry_error = status_retry_error(status, method, redacted_uri, headers);
        self.schedule_retry(
            RetryContext {
                context,
                retry_policy,
                total_timeout,
                request_started_at,
                method,
                redacted_uri,
                max_attempts,
            },
            &retry_plan.decision,
            retry_plan.delay,
            attempt,
            &retry_error,
        )
        .await
    }

    async fn read_response_body_with_retry(
        &self,
        body: Incoming,
        read_context: ReadBodyRetryContext<'_>,
    ) -> Result<Option<Bytes>, Error> {
        let ReadBodyRetryContext {
            context,
            max_response_body_bytes,
            timeout_value,
            total_timeout,
            request_started_at,
            method,
            redacted_uri,
            retry_policy,
            max_attempts,
            attempt,
        } = read_context;
        let Some(read_timeout) = phase_timeout(timeout_value, total_timeout, request_started_at)
        else {
            let error = deadline_exceeded_error(total_timeout, method, redacted_uri);
            self.run_error_interceptors(context, &error);
            return Err(error);
        };

        match timeout(
            read_timeout,
            read_all_body_limited(body, max_response_body_bytes),
        )
        .await
        {
            Ok(Ok(body)) => Ok(Some(body)),
            Ok(Err(ReadBodyError::Read(source))) => {
                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                let retry_decision =
                    response_body_read_retry_decision(*attempt, max_attempts, method, redacted_uri);
                if self
                    .schedule_retry(
                        RetryContext {
                            context,
                            retry_policy,
                            total_timeout,
                            request_started_at,
                            method,
                            redacted_uri,
                            max_attempts,
                        },
                        &retry_decision,
                        self.backoff_source
                            .backoff_for_retry(retry_policy, *attempt),
                        attempt,
                        &error,
                    )
                    .await?
                {
                    return Ok(None);
                }
                self.run_error_interceptors(context, &error);
                Err(error)
            }
            Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                let error = Error::ResponseBodyTooLarge {
                    limit_bytes: max_response_body_bytes,
                    actual_bytes,
                    method: method.clone(),
                    uri: redacted_uri.to_owned(),
                };
                self.run_error_interceptors(context, &error);
                Err(error)
            }
            Err(_) => {
                let error = if total_timeout_expired(total_timeout, request_started_at) {
                    deadline_exceeded_error(total_timeout, method, redacted_uri)
                } else {
                    Error::Timeout {
                        phase: TimeoutPhase::ResponseBody,
                        timeout_ms: read_timeout.as_millis(),
                        method: method.clone(),
                        uri: redacted_uri.to_owned(),
                    }
                };
                if matches!(error, Error::DeadlineExceeded { .. }) {
                    self.run_error_interceptors(context, &error);
                    return Err(error);
                }
                let retry_decision = timeout_retry_decision(
                    *attempt,
                    max_attempts,
                    method,
                    redacted_uri,
                    TimeoutPhase::ResponseBody,
                );
                if self
                    .schedule_retry(
                        RetryContext {
                            context,
                            retry_policy,
                            total_timeout,
                            request_started_at,
                            method,
                            redacted_uri,
                            max_attempts,
                        },
                        &retry_decision,
                        self.backoff_source
                            .backoff_for_retry(retry_policy, *attempt),
                        attempt,
                        &error,
                    )
                    .await?
                {
                    return Ok(None);
                }
                self.run_error_interceptors(context, &error);
                Err(error)
            }
        }
    }

    async fn read_decoded_response_body_with_retry(
        &self,
        body: Incoming,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        read_context: ReadBodyRetryContext<'_>,
    ) -> Result<Option<Bytes>, Error> {
        let max_response_body_bytes = read_context.max_response_body_bytes;
        let context = read_context.context;
        let response_body = match self
            .read_response_body_with_retry(body, read_context)
            .await?
        {
            Some(body) => body,
            None => return Ok(None),
        };
        let should_decode_response_body =
            should_decode_content_encoded_body(context.method(), status, response_body.len());
        let response_body = self.decode_response_body_limited(
            response_body,
            response_headers,
            max_response_body_bytes,
            status,
            context,
        )?;
        if should_decode_response_body && response_headers.contains_key(CONTENT_ENCODING) {
            remove_content_encoding_headers(response_headers);
        }
        Ok(Some(response_body))
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
        let base_url = select_base_url(
            self.endpoint_selector.as_ref(),
            &method,
            &path,
            &self.base_url,
        )?;
        let (uri_text, uri) = resolve_uri(&base_url, &path)?;
        let redacted_uri_text = redact_uri_for_logs(&uri_text);
        let mut merged_headers = merge_headers(&self.default_headers, &headers);
        let auto_accept_encoding = execution_options
            .auto_accept_encoding
            .unwrap_or(self.buffered_auto_accept_encoding);
        if auto_accept_encoding {
            ensure_accept_encoding_async(&method, &mut merged_headers);
        }
        let body = body.unwrap_or_else(RequestBody::empty);
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, false);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let effective_total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let _global_permit = match self
            .acquire_global_request_permit(
                effective_total_timeout,
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
            .send_request_with_retry(
                RetryRequestInput {
                    method,
                    uri,
                    redacted_uri_text,
                    merged_headers,
                    body,
                    execution_options,
                },
                request_started_at,
            )
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
        let base_url = select_base_url(
            self.endpoint_selector.as_ref(),
            &method,
            &path,
            &self.base_url,
        )?;
        let (uri_text, uri) = resolve_uri(&base_url, &path)?;
        let redacted_uri_text = redact_uri_for_logs(&uri_text);
        let mut merged_headers = merge_headers(&self.default_headers, &headers);
        let auto_accept_encoding = execution_options
            .auto_accept_encoding
            .unwrap_or(self.stream_auto_accept_encoding);
        if auto_accept_encoding {
            ensure_accept_encoding_async(&method, &mut merged_headers);
        }
        let body = body.unwrap_or_else(RequestBody::empty);
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, true);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let effective_total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let global_permit = match self
            .acquire_global_request_permit(
                effective_total_timeout,
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
        let expected_method = method.clone();
        let expected_redacted_uri = redacted_uri_text.clone();

        let result = match self
            .send_request_with_retry_mode(
                RetryRequestInput {
                    method,
                    uri,
                    redacted_uri_text,
                    merged_headers,
                    body,
                    execution_options,
                },
                ResponseMode::Stream,
                Some(global_permit),
                request_started_at,
            )
            .await
        {
            Ok(RetryResponse::Stream(response)) => Ok(response),
            Ok(RetryResponse::Buffered(_)) => Err(response_mode_mismatch_error(
                &expected_method,
                &expected_redacted_uri,
                "stream",
            )),
            Err(error) => Err(error),
        };
        self.metrics
            .record_request_completed_stream(&result, request_started_at.elapsed());
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

    async fn send_request_with_retry(
        &self,
        input: RetryRequestInput,
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
        input: RetryRequestInput,
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
        let timeout_value = execution_options
            .request_timeout
            .unwrap_or(self.request_timeout)
            .max(Duration::from_millis(1));
        let total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let max_response_body_bytes = execution_options
            .max_response_body_bytes
            .unwrap_or(self.max_response_body_bytes)
            .max(1);
        let (mut buffered_body, mut streaming_body) = match body {
            RequestBody::Buffered(body) => (Some(body), None),
            RequestBody::Streaming(body) => (None, Some(body)),
        };
        let body_replayable = buffered_body.is_some();
        let retry_policy = execution_options
            .retry_policy
            .unwrap_or_else(|| self.retry_policy.clone());
        let redirect_policy = execution_options
            .redirect_policy
            .unwrap_or(self.redirect_policy);
        let status_policy =
            effective_status_policy(execution_options.status_policy, self.default_status_policy);
        let mut max_attempts = if self
            .retry_eligibility
            .supports_retry(&method, &merged_headers)
            && body_replayable
        {
            retry_policy.configured_max_attempts()
        } else {
            1
        };
        let stream_total_timeout_ms = total_timeout.map(|timeout| timeout.as_millis());
        let stream_deadline_at =
            total_timeout.and_then(|timeout| request_started_at.checked_add(timeout));
        let mut attempt = 1_usize;
        let mut redirect_count = 0_usize;
        let mut current_method = method;
        let mut current_uri = uri;
        let mut current_redacted_uri = redacted_uri_text;
        let mut current_headers = merged_headers;
        let mut stream_global_permit = stream_global_permit;

        while attempt <= max_attempts {
            let span = if matches!(response_mode, ResponseMode::Stream) {
                info_span!(
                    "reqx.request.stream",
                    client = %self.client_name,
                    method = %current_method,
                    uri = %current_redacted_uri,
                    attempt = attempt,
                    max_attempts = max_attempts
                )
            } else {
                info_span!(
                    "reqx.request",
                    client = %self.client_name,
                    method = %current_method,
                    uri = %current_redacted_uri,
                    attempt = attempt,
                    max_attempts = max_attempts
                )
            };
            let _enter = span.enter();
            let started = Instant::now();
            let context = RequestContext::new(
                current_method.clone(),
                current_redacted_uri.clone(),
                attempt,
                max_attempts,
                redirect_count,
            );
            self.run_request_start_observers(&context);

            debug!("sending request");
            let rate_limit_host = rate_limit_bucket_key(&current_uri);
            if let Err(error) = self
                .acquire_rate_limit_slot(
                    rate_limit_host.as_deref(),
                    total_timeout,
                    request_started_at,
                    &current_method,
                    &current_redacted_uri,
                )
                .await
            {
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            let Some(transport_timeout) =
                phase_timeout(timeout_value, total_timeout, request_started_at)
            else {
                let error =
                    deadline_exceeded_error(total_timeout, &current_method, &current_redacted_uri);
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };
            let mut circuit_attempt =
                match self.begin_circuit_attempt(&current_method, &current_redacted_uri) {
                    Ok(attempt) => attempt,
                    Err(error) => {
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                };
            let host_key = rate_limit_bucket_key(&current_uri);
            let host_permit = match self
                .acquire_host_request_permit(
                    host_key.as_deref(),
                    total_timeout,
                    request_started_at,
                    &current_method,
                    &current_redacted_uri,
                )
                .await
            {
                Ok(permit) => permit,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let mut adaptive_attempt = match self
                .begin_adaptive_attempt(
                    total_timeout,
                    request_started_at,
                    &current_method,
                    &current_redacted_uri,
                )
                .await
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let mut attempt_headers = current_headers.clone();
            self.apply_http_proxy_auth_header(&current_uri, &mut attempt_headers);
            self.run_request_interceptors(&context, &mut attempt_headers);
            let request_body = if let Some(body) = &buffered_body {
                buffered_req_body(body.clone())
            } else {
                streaming_body.take().unwrap_or_else(empty_req_body)
            };
            let request = build_http_request(
                current_method.clone(),
                current_uri.clone(),
                &attempt_headers,
                request_body,
            )?;
            let response = match self
                .send_transport_request(transport_timeout, request)
                .await
            {
                Ok(response) => response,
                Err(TransportRequestError::Transport(source)) => {
                    let kind = classify_transport_error(&source);
                    let error = Error::Transport {
                        kind,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        source: Box::new(source),
                    };
                    let Some(retry_decision) = transport_retry_decision_from_error(
                        attempt,
                        max_attempts,
                        &current_method,
                        &current_redacted_uri,
                        &error,
                    ) else {
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    };
                    if self
                        .schedule_retry(
                            RetryContext {
                                context: &context,
                                retry_policy: &retry_policy,
                                total_timeout,
                                request_started_at,
                                method: &current_method,
                                redacted_uri: &current_redacted_uri,
                                max_attempts,
                            },
                            &retry_decision,
                            self.backoff_source
                                .backoff_for_retry(&retry_policy, attempt),
                            &mut attempt,
                            &error,
                        )
                        .await?
                    {
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Err(TransportRequestError::Timeout) => {
                    let error = transport_timeout_error(
                        total_timeout,
                        request_started_at,
                        transport_timeout.as_millis(),
                        &current_method,
                        &current_redacted_uri,
                    );
                    let Some(retry_decision) = transport_retry_decision_from_error(
                        attempt,
                        max_attempts,
                        &current_method,
                        &current_redacted_uri,
                        &error,
                    ) else {
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    };
                    if self
                        .schedule_retry(
                            RetryContext {
                                context: &context,
                                retry_policy: &retry_policy,
                                total_timeout,
                                request_started_at,
                                method: &current_method,
                                redacted_uri: &current_redacted_uri,
                                max_attempts,
                            },
                            &retry_decision,
                            self.backoff_source
                                .backoff_for_retry(&retry_policy, attempt),
                            &mut attempt,
                            &error,
                        )
                        .await?
                    {
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            let status = response.status();
            let mut response_headers = response.headers().clone();
            let redirect_action = match next_redirect_action(RedirectInput {
                redirect_policy,
                redirect_count,
                status,
                current_method: &current_method,
                current_uri: &current_uri,
                current_redacted_uri: &current_redacted_uri,
                response_headers: &response_headers,
                body_replayable,
            }) {
                Ok(action) => action,
                Err(error) => {
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            if let Some(redirect_action) = redirect_action {
                self.run_response_interceptors(&context, status, &response_headers);
                if let Some(attempt_guard) = circuit_attempt.take() {
                    attempt_guard.mark_success();
                }
                if let Some(adaptive_guard) = adaptive_attempt.take() {
                    adaptive_guard.mark_success();
                }
                let method_changed_to_get = apply_redirect_transition(
                    RedirectTransitionInput {
                        retry_eligibility: self.retry_eligibility.as_ref(),
                        retry_policy: &retry_policy,
                        max_attempts: &mut max_attempts,
                        body_replayable,
                        current_headers: &mut current_headers,
                        current_method: &mut current_method,
                        current_uri: &mut current_uri,
                        current_redacted_uri: &mut current_redacted_uri,
                        redirect_count: &mut redirect_count,
                    },
                    redirect_action,
                );
                if method_changed_to_get {
                    buffered_body = None;
                    streaming_body = None;
                }
                continue;
            }

            let mut ran_response_interceptors = false;
            let mut observed_server_throttle = false;
            let mut evaluated_status_retry = false;

            if matches!(response_mode, ResponseMode::Stream) {
                self.run_response_interceptors(&context, status, &response_headers);
                ran_response_interceptors = true;

                if status.is_success() {
                    if let Some(attempt_guard) = circuit_attempt.take() {
                        attempt_guard.mark_success();
                    }
                    if let Some(adaptive_guard) = adaptive_attempt.take() {
                        adaptive_guard.mark_success();
                    }
                    self.record_successful_request_for_resilience();
                    return Ok(RetryResponse::Stream(ResponseStream::new(
                        status,
                        response_headers,
                        response.into_body(),
                        ResponseStreamContext {
                            method: current_method.clone(),
                            uri_raw: current_uri.to_string(),
                            uri_redacted: current_redacted_uri.clone(),
                            timeout_ms: transport_timeout.as_millis(),
                            total_timeout_ms: stream_total_timeout_ms,
                            deadline_at: stream_deadline_at,
                            permits: StreamPermits::new(
                                stream_global_permit.take(),
                                Some(host_permit),
                            ),
                        },
                    )));
                }

                self.observe_server_throttle(
                    &context,
                    status,
                    &response_headers,
                    rate_limit_host.as_deref(),
                    self.backoff_source
                        .backoff_for_retry(&retry_policy, attempt),
                );
                observed_server_throttle = true;

                evaluated_status_retry = true;
                if self
                    .schedule_status_retry(
                        StatusRetryContext {
                            context: &context,
                            retry_policy: &retry_policy,
                            total_timeout,
                            request_started_at,
                            method: &current_method,
                            redacted_uri: &current_redacted_uri,
                            status,
                            headers: &response_headers,
                            max_attempts,
                        },
                        &mut attempt,
                    )
                    .await?
                {
                    continue;
                }
                if should_return_non_success_response(status_policy) {
                    self.maybe_record_terminal_response_success(status, &retry_policy);
                    if let Some(attempt_guard) = circuit_attempt.take() {
                        attempt_guard.mark_success();
                    }
                    if let Some(adaptive_guard) = adaptive_attempt.take() {
                        adaptive_guard.mark_success();
                    }
                    return Ok(RetryResponse::Stream(ResponseStream::new(
                        status,
                        response_headers,
                        response.into_body(),
                        ResponseStreamContext {
                            method: current_method.clone(),
                            uri_raw: current_uri.to_string(),
                            uri_redacted: current_redacted_uri.clone(),
                            timeout_ms: transport_timeout.as_millis(),
                            total_timeout_ms: stream_total_timeout_ms,
                            deadline_at: stream_deadline_at,
                            permits: StreamPermits::new(
                                stream_global_permit.take(),
                                Some(host_permit),
                            ),
                        },
                    )));
                }
            }

            let response_body = match self
                .read_decoded_response_body_with_retry(
                    response.into_body(),
                    &mut response_headers,
                    status,
                    ReadBodyRetryContext {
                        context: &context,
                        max_response_body_bytes,
                        timeout_value,
                        total_timeout,
                        request_started_at,
                        method: &current_method,
                        redacted_uri: &current_redacted_uri,
                        retry_policy: &retry_policy,
                        max_attempts,
                        attempt: &mut attempt,
                    },
                )
                .await?
            {
                Some(body) => body,
                None => continue,
            };

            if matches!(response_mode, ResponseMode::Buffered) {
                debug!(
                    status = status.as_u16(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "request completed"
                );
            }
            if !ran_response_interceptors {
                self.run_response_interceptors(&context, status, &response_headers);
            }

            if !status.is_success() {
                if !observed_server_throttle {
                    self.observe_server_throttle(
                        &context,
                        status,
                        &response_headers,
                        rate_limit_host.as_deref(),
                        self.backoff_source
                            .backoff_for_retry(&retry_policy, attempt),
                    );
                }
                if !evaluated_status_retry {
                    if self
                        .schedule_status_retry(
                            StatusRetryContext {
                                context: &context,
                                retry_policy: &retry_policy,
                                total_timeout,
                                request_started_at,
                                method: &current_method,
                                redacted_uri: &current_redacted_uri,
                                status,
                                headers: &response_headers,
                                max_attempts,
                            },
                            &mut attempt,
                        )
                        .await?
                    {
                        continue;
                    }
                    if should_return_non_success_response(status_policy)
                        && matches!(response_mode, ResponseMode::Buffered)
                    {
                        self.maybe_record_terminal_response_success(status, &retry_policy);
                        if let Some(attempt_guard) = circuit_attempt.take() {
                            attempt_guard.mark_success();
                        }
                        if let Some(adaptive_guard) = adaptive_attempt.take() {
                            adaptive_guard.mark_success();
                        }
                        return Ok(RetryResponse::Buffered(Response::new(
                            status,
                            response_headers,
                            response_body,
                        )));
                    }
                }

                let error = http_status_error(
                    status,
                    &current_method,
                    &current_redacted_uri,
                    &response_headers,
                    truncate_body(&response_body),
                );
                if should_mark_non_success_for_resilience(&retry_policy, status) {
                    if let Some(attempt_guard) = circuit_attempt.take() {
                        attempt_guard.mark_success();
                    }
                    if let Some(adaptive_guard) = adaptive_attempt.take() {
                        adaptive_guard.mark_success();
                    }
                    self.maybe_record_terminal_response_success(status, &retry_policy);
                }
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }

            if let Some(attempt_guard) = circuit_attempt.take() {
                attempt_guard.mark_success();
            }
            if let Some(adaptive_guard) = adaptive_attempt.take() {
                adaptive_guard.mark_success();
            }
            self.record_successful_request_for_resilience();
            return Ok(RetryResponse::Buffered(Response::new(
                status,
                response_headers,
                response_body,
            )));
        }

        let error = deadline_exceeded_error(total_timeout, &current_method, &current_redacted_uri);
        let context = RequestContext::new(
            current_method,
            current_redacted_uri,
            attempt,
            max_attempts,
            redirect_count,
        );
        self.run_error_interceptors(&context, &error);
        Err(error)
    }
}
