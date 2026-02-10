use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, Uri};
use hyper::body::Incoming;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_util::client::legacy::Client;
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_util::rt::TokioExecutor;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tracing::{debug, info_span, warn};

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use hyper_rustls::HttpsConnectorBuilder;

use crate::ReqxResult;
use crate::body::{
    DecodeContentEncodingError, ReadBodyError, ReqBody, RequestBody, buffered_req_body,
    build_http_request, decode_content_encoded_body_limited, empty_req_body, read_all_body_limited,
};
use crate::error::{HttpClientError, TimeoutPhase};
use crate::limiters::{RequestLimiters, RequestPermits};
use crate::metrics::{HttpClientMetrics, HttpClientMetricsSnapshot};
use crate::otel::OtelTelemetry;
use crate::policy::{HttpInterceptor, RedirectPolicy, RequestContext};
#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use crate::proxy::ProxyConnector;
use crate::proxy::{NoProxyRule, ProxyConfig};
use crate::rate_limit::{
    RateLimitPolicy, RateLimiter, ServerThrottleScope, server_throttle_scope_from_headers,
};
use crate::request::RequestBuilder;
use crate::resilience::{
    AdaptiveConcurrencyPolicy, CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
};
use crate::response::{HttpResponse, HttpResponseStream};
use crate::retry::{
    PermissiveRetryEligibility, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
use crate::tls::{
    TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore, tls_config_error,
};
use crate::util::{
    bounded_retry_delay, classify_transport_error, deadline_exceeded_error, ensure_accept_encoding,
    is_redirect_status, lock_unpoisoned, merge_headers, parse_header_name, parse_header_value,
    parse_retry_after, phase_timeout, rate_limit_bucket_key, redact_uri_for_logs,
    redirect_location, redirect_method, resolve_redirect_uri, resolve_uri, same_origin,
    sanitize_headers_for_redirect, truncate_body, validate_base_url,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
const DEFAULT_CLIENT_NAME: &str = "reqx";
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

const fn default_tls_backend() -> TlsBackend {
    #[cfg(feature = "async-tls-rustls-ring")]
    {
        return TlsBackend::RustlsRing;
    }
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    {
        return TlsBackend::RustlsAwsLcRs;
    }
    #[cfg(all(
        not(feature = "async-tls-rustls-ring"),
        not(feature = "async-tls-rustls-aws-lc-rs"),
        feature = "async-tls-native"
    ))]
    {
        return TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    TlsBackend::RustlsRing
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
) -> ReqxResult<usize> {
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
) -> ReqxResult<rustls::RootCertStore> {
    if !tls_options.root_certificates.is_empty() && tls_options.root_store != TlsRootStore::Specific
    {
        return Err(tls_config_error(
            tls_backend,
            "custom root CAs require tls_root_store(TlsRootStore::Specific)",
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

    let custom_added = if tls_options.root_store == TlsRootStore::Specific {
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
) -> ReqxResult<rustls::ClientConfig> {
    use rustls::pki_types::pem::PemObject;

    let root_store = build_rustls_root_store(tls_backend, tls_options)?;

    let config_builder = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|source| HttpClientError::TlsBackendInit {
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
type RustlsHyperClient = Client<RustlsHttpsConnector, ReqBody>;

#[cfg(feature = "async-tls-native")]
type NativeHttpsConnector = hyper_tls::HttpsConnector<ProxyConnector>;
#[cfg(feature = "async-tls-native")]
type NativeHyperClient = Client<NativeHttpsConnector, ReqBody>;

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
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        #[cfg(not(any(
            feature = "async-tls-native",
            feature = "async-tls-rustls-ring",
            feature = "async-tls-rustls-aws-lc-rs"
        )))]
        let _ = &request;

        match self {
            #[cfg(any(
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs"
            ))]
            Self::Rustls(client) => client.request(request).await,
            #[cfg(feature = "async-tls-native")]
            Self::Native(client) => client.request(request).await,
            #[cfg(not(any(
                feature = "async-tls-native",
                feature = "async-tls-rustls-ring",
                feature = "async-tls-rustls-aws-lc-rs"
            )))]
            _ => unreachable!("no TLS transport backend is compiled"),
        }
    }
}

enum TransportRequestError {
    Transport(hyper_util::client::legacy::Error),
    Timeout,
}

fn decode_content_encoding_error(
    encoding: String,
    message: String,
    method: &Method,
    uri: &str,
) -> HttpClientError {
    HttpClientError::DecodeContentEncoding {
        encoding,
        message,
        method: method.clone(),
        uri: uri.to_owned(),
    }
}

fn decode_response_body_error(
    error: DecodeContentEncodingError,
    max_bytes: usize,
    method: &Method,
    uri: &str,
) -> HttpClientError {
    match error {
        DecodeContentEncodingError::Decode { encoding, message } => {
            decode_content_encoding_error(encoding, message, method, uri)
        }
        DecodeContentEncodingError::TooLarge { actual_bytes } => {
            HttpClientError::ResponseBodyTooLarge {
                limit_bytes: max_bytes,
                actual_bytes,
                method: method.clone(),
                uri: uri.to_owned(),
            }
        }
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
) -> ReqxResult<TransportClient> {
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
    let transport = Client::builder(TokioExecutor::new())
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
) -> ReqxResult<TransportClient> {
    Err(HttpClientError::TlsBackendUnavailable {
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
) -> ReqxResult<TransportClient> {
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
    let transport = Client::builder(TokioExecutor::new())
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
) -> ReqxResult<TransportClient> {
    Err(HttpClientError::TlsBackendUnavailable {
        backend: TlsBackend::RustlsAwsLcRs.as_str(),
    })
}

#[cfg(feature = "async-tls-native")]
fn build_native_tls_connector(
    tls_options: &TlsOptions,
) -> ReqxResult<hyper_tls::native_tls::TlsConnector> {
    let mut connector_builder = hyper_tls::native_tls::TlsConnector::builder();

    if !tls_options.root_certificates.is_empty() && tls_options.root_store != TlsRootStore::Specific
    {
        return Err(tls_config_error(
            TlsBackend::NativeTls,
            "custom root CAs require tls_root_store(TlsRootStore::Specific)",
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
        .map_err(|source| HttpClientError::TlsBackendInit {
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
) -> ReqxResult<TransportClient> {
    let connector = ProxyConnector::new(proxy_config, connect_timeout);
    let https = if tls_options.has_customizations() {
        let tls_connector = build_native_tls_connector(tls_options)?;
        hyper_tls::HttpsConnector::from((connector, tls_connector.into()))
    } else {
        hyper_tls::HttpsConnector::new_with_connector(connector)
    };
    let transport = Client::builder(TokioExecutor::new())
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
) -> ReqxResult<TransportClient> {
    Err(HttpClientError::TlsBackendUnavailable {
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
) -> ReqxResult<TransportClient> {
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
struct AdaptiveConcurrencyState {
    in_flight: usize,
    current_limit: usize,
    ewma_latency_ms: f64,
}

#[derive(Debug)]
struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    notify: Notify,
}

impl AdaptiveConcurrencyController {
    fn new(policy: AdaptiveConcurrencyPolicy) -> Self {
        let initial_limit = policy
            .initial_limit_value()
            .clamp(policy.min_limit_value(), policy.max_limit_value());
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState {
                in_flight: 0,
                current_limit: initial_limit,
                ewma_latency_ms: 0.0,
            }),
            notify: Notify::new(),
        }
    }

    async fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        loop {
            {
                let mut state = lock_unpoisoned(&self.state);
                if state.in_flight < state.current_limit {
                    state.in_flight = state.in_flight.saturating_add(1);
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
        state.in_flight = state.in_flight.saturating_sub(1);

        let latency_ms = latency.as_secs_f64() * 1000.0;
        if state.ewma_latency_ms <= f64::EPSILON {
            state.ewma_latency_ms = latency_ms;
        } else {
            state.ewma_latency_ms = state.ewma_latency_ms * 0.8 + latency_ms * 0.2;
        }

        let threshold_ms = self.policy.high_latency_threshold_value().as_secs_f64() * 1000.0;
        let should_decrease = !success || state.ewma_latency_ms > threshold_ms;
        if should_decrease {
            let decreased =
                (state.current_limit as f64 * self.policy.decrease_ratio_value()).floor() as usize;
            state.current_limit = decreased.max(self.policy.min_limit_value());
        } else {
            state.current_limit = state
                .current_limit
                .saturating_add(self.policy.increase_step_value())
                .min(self.policy.max_limit_value());
        }

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
}

pub struct HttpClientBuilder {
    base_url: String,
    default_headers: HeaderMap,
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
    retry_policy: RetryPolicy,
    retry_eligibility: Arc<dyn RetryEligibility>,
    retry_budget_policy: Option<RetryBudgetPolicy>,
    circuit_breaker_policy: Option<CircuitBreakerPolicy>,
    adaptive_concurrency_policy: Option<AdaptiveConcurrencyPolicy>,
    global_rate_limit_policy: Option<RateLimitPolicy>,
    per_host_rate_limit_policy: Option<RateLimitPolicy>,
    server_throttle_scope: ServerThrottleScope,
    redirect_policy: RedirectPolicy,
    tls_backend: TlsBackend,
    tls_options: TlsOptions,
    client_name: String,
    max_in_flight: Option<usize>,
    max_in_flight_per_host: Option<usize>,
    metrics_enabled: bool,
    otel_enabled: bool,
    interceptors: Vec<Arc<dyn HttpInterceptor>>,
}

impl HttpClientBuilder {
    pub(crate) fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            default_headers: HeaderMap::new(),
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
            retry_policy: RetryPolicy::standard(),
            retry_eligibility: Arc::new(StrictRetryEligibility),
            retry_budget_policy: None,
            circuit_breaker_policy: None,
            adaptive_concurrency_policy: None,
            global_rate_limit_policy: None,
            per_host_rate_limit_policy: None,
            server_throttle_scope: ServerThrottleScope::Auto,
            redirect_policy: RedirectPolicy::none(),
            tls_backend: default_tls_backend(),
            tls_options: TlsOptions::default(),
            client_name: DEFAULT_CLIENT_NAME.to_owned(),
            max_in_flight: None,
            max_in_flight_per_host: None,
            metrics_enabled: false,
            otel_enabled: false,
            interceptors: Vec::new(),
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

    pub fn try_proxy_authorization(self, proxy_authorization: &str) -> ReqxResult<Self> {
        let proxy_authorization = parse_header_value("proxy-authorization", proxy_authorization)?;
        Ok(self.proxy_authorization(proxy_authorization))
    }

    pub fn no_proxy<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.no_proxy_rules = rules
            .into_iter()
            .filter_map(|rule| NoProxyRule::parse(rule.as_ref()))
            .collect();
        self
    }

    pub fn add_no_proxy(mut self, rule: impl AsRef<str>) -> Self {
        if let Some(rule) = NoProxyRule::parse(rule.as_ref()) {
            self.no_proxy_rules.push(rule);
        }
        self
    }

    pub fn default_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.default_headers.insert(name, value);
        self
    }

    pub fn try_default_header(self, name: &str, value: &str) -> ReqxResult<Self> {
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

    pub fn adaptive_concurrency(
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

    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
        self
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

    pub fn interceptor_arc(mut self, interceptor: Arc<dyn HttpInterceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    pub fn interceptor<I>(self, interceptor: I) -> Self
    where
        I: HttpInterceptor + 'static,
    {
        self.interceptor_arc(Arc::new(interceptor))
    }

    pub fn try_build(self) -> ReqxResult<HttpClient> {
        validate_base_url(&self.base_url)?;

        let proxy_config = self.http_proxy.map(|uri| ProxyConfig {
            uri,
            authorization: self.proxy_authorization,
            no_proxy_rules: self.no_proxy_rules,
        });
        let transport = build_transport_client(
            self.tls_backend,
            proxy_config,
            &self.tls_options,
            self.connect_timeout,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.http2_only,
        )?;
        let otel = if self.otel_enabled {
            OtelTelemetry::enabled(self.client_name.clone())
        } else {
            OtelTelemetry::disabled()
        };

        Ok(HttpClient {
            base_url: self.base_url,
            default_headers: self.default_headers,
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
            client_name: self.client_name,
            tls_backend: self.tls_backend,
            transport,
            request_limiters: RequestLimiters::new(self.max_in_flight, self.max_in_flight_per_host),
            metrics: HttpClientMetrics::with_options(self.metrics_enabled, otel),
            interceptors: self.interceptors,
        })
    }

    #[track_caller]
    pub fn build(self) -> HttpClient {
        self.try_build().unwrap_or_else(|error| {
            panic!("failed to build reqx http client: {error}; use try_build() to handle configuration errors")
        })
    }
}

#[derive(Clone)]
pub struct HttpClient {
    base_url: String,
    default_headers: HeaderMap,
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
    client_name: String,
    tls_backend: TlsBackend,
    transport: TransportClient,
    request_limiters: Option<RequestLimiters>,
    metrics: HttpClientMetrics,
    interceptors: Vec<Arc<dyn HttpInterceptor>>,
}

impl HttpClient {
    pub fn builder(base_url: impl Into<String>) -> HttpClientBuilder {
        HttpClientBuilder::new(base_url)
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

    pub fn metrics_snapshot(&self) -> HttpClientMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn tls_backend(&self) -> TlsBackend {
        self.tls_backend
    }

    fn run_request_interceptors(&self, context: &RequestContext, headers: &mut HeaderMap) {
        for interceptor in &self.interceptors {
            interceptor.on_request(context, headers);
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

    fn run_error_interceptors(&self, context: &RequestContext, error: &HttpClientError) {
        for interceptor in &self.interceptors {
            interceptor.on_error(context, error);
        }
    }

    fn record_successful_request_for_resilience(&self) {
        if let Some(retry_budget) = &self.retry_budget {
            retry_budget.record_success();
        }
    }

    fn try_consume_retry_budget(&self, method: &Method, uri: &str) -> Result<(), HttpClientError> {
        let Some(retry_budget) = &self.retry_budget else {
            return Ok(());
        };
        if retry_budget.try_consume_retry() {
            Ok(())
        } else {
            Err(HttpClientError::RetryBudgetExhausted {
                method: method.clone(),
                uri: uri.to_owned(),
            })
        }
    }

    fn begin_circuit_attempt(
        &self,
        method: &Method,
        uri: &str,
    ) -> Result<Option<crate::resilience::CircuitAttempt>, HttpClientError> {
        let Some(circuit_breaker) = &self.circuit_breaker else {
            return Ok(None);
        };

        match circuit_breaker.begin() {
            Ok(attempt) => Ok(Some(attempt)),
            Err(retry_after) => Err(HttpClientError::CircuitOpen {
                method: method.clone(),
                uri: uri.to_owned(),
                retry_after_ms: retry_after.as_millis(),
            }),
        }
    }

    async fn begin_adaptive_attempt(&self) -> Option<AdaptiveConcurrencyPermit> {
        let controller = self.adaptive_concurrency.as_ref()?;
        Some(controller.acquire().await)
    }

    async fn acquire_rate_limit_slot(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<(), HttpClientError> {
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
        let throttle_delay =
            parse_retry_after(headers, SystemTime::now()).unwrap_or(fallback_delay);
        rate_limiter.observe_server_throttle(
            host,
            throttle_delay,
            self.server_throttle_scope,
            server_throttle_scope_from_headers(headers),
        );
    }

    async fn acquire_request_permits(
        &self,
        host: Option<&str>,
    ) -> Result<RequestPermits, HttpClientError> {
        match &self.request_limiters {
            Some(limiters) => limiters.acquire(host).await,
            None => Ok(RequestPermits {
                _global: None,
                _host: None,
            }),
        }
    }

    async fn send_transport_request(
        &self,
        transport_timeout: Duration,
        request: Request<ReqBody>,
    ) -> Result<Response<Incoming>, TransportRequestError> {
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
    ) -> Result<HttpResponse, HttpClientError> {
        let (uri_text, uri) = resolve_uri(&self.base_url, &path)?;
        let redacted_uri_text = redact_uri_for_logs(&uri_text);
        let mut merged_headers = merge_headers(&self.default_headers, &headers);
        ensure_accept_encoding(&mut merged_headers);
        let body = body.unwrap_or_else(RequestBody::empty);
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, false);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let host = uri.host().map(|item| item.to_ascii_lowercase());
        let _permits = match self.acquire_request_permits(host.as_deref()).await {
            Ok(permits) => permits,
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
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body,
                execution_options,
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
    ) -> Result<HttpResponseStream, HttpClientError> {
        let (uri_text, uri) = resolve_uri(&self.base_url, &path)?;
        let redacted_uri_text = redact_uri_for_logs(&uri_text);
        let mut merged_headers = merge_headers(&self.default_headers, &headers);
        ensure_accept_encoding(&mut merged_headers);
        let body = body.unwrap_or_else(RequestBody::empty);
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, true);
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let host = uri.host().map(|item| item.to_ascii_lowercase());
        let _permits = match self.acquire_request_permits(host.as_deref()).await {
            Ok(permits) => permits,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                self.metrics
                    .finish_otel_request_span_error(otel_span, &error);
                return Err(error);
            }
        };

        let result = self
            .send_request_stream_with_retry(
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body,
                execution_options,
            )
            .await;
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

    async fn send_request_stream_with_retry(
        &self,
        method: Method,
        uri: Uri,
        redacted_uri_text: String,
        merged_headers: HeaderMap,
        body: RequestBody,
        execution_options: RequestExecutionOptions,
    ) -> Result<HttpResponseStream, HttpClientError> {
        let timeout_value = execution_options
            .request_timeout
            .unwrap_or(self.request_timeout)
            .max(Duration::from_millis(1));
        let total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let max_response_body_bytes = execution_options
            .max_response_body_bytes
            .unwrap_or(self.max_response_body_bytes)
            .max(1);
        let (buffered_body, mut streaming_body) = match body {
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
        let mut max_attempts = if self
            .retry_eligibility
            .supports_retry(&method, &merged_headers)
            && body_replayable
        {
            retry_policy.max_attempts_value()
        } else {
            1
        };
        let request_started_at = Instant::now();
        let mut attempt = 1_usize;
        let mut redirect_count = 0_usize;
        let mut current_method = method;
        let mut current_uri = uri;
        let mut current_redacted_uri = redacted_uri_text;
        let mut current_headers = merged_headers;

        while attempt <= max_attempts {
            let span = info_span!(
                "reqx.request.stream",
                client = %self.client_name,
                method = %current_method,
                uri = %current_redacted_uri,
                attempt = attempt,
                max_attempts = max_attempts
            );
            let _enter = span.enter();
            let context = RequestContext::new(
                current_method.clone(),
                current_redacted_uri.clone(),
                attempt,
                max_attempts,
                redirect_count,
            );
            debug!("sending stream request");
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
            let mut adaptive_attempt = self.begin_adaptive_attempt().await;
            let mut attempt_headers = current_headers.clone();
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
                    let error = HttpClientError::Transport {
                        kind,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        source: Box::new(source),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: Some(kind),
                        timeout_phase: None,
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Err(TransportRequestError::Timeout) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::Transport,
                        timeout_ms: transport_timeout.as_millis(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::Transport),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            let status = response.status();
            let response_headers = response.headers().clone();
            if redirect_policy.enabled() && is_redirect_status(status) {
                if redirect_count >= redirect_policy.max_redirects() {
                    let error = HttpClientError::RedirectLimitExceeded {
                        max_redirects: redirect_policy.max_redirects(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                if !body_replayable
                    && !matches!(
                        current_method,
                        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                    )
                {
                    let error = HttpClientError::RedirectBodyNotReplayable {
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                let Some(location) = redirect_location(&response_headers) else {
                    let error = HttpClientError::MissingRedirectLocation {
                        status: status.as_u16(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                let Some(next_uri) = resolve_redirect_uri(&current_uri, &location) else {
                    let error = HttpClientError::InvalidRedirectLocation {
                        location,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                self.run_response_interceptors(&context, status, &response_headers);
                if let Some(attempt_guard) = circuit_attempt.take() {
                    attempt_guard.mark_success();
                }
                if let Some(adaptive_guard) = adaptive_attempt.take() {
                    adaptive_guard.mark_success();
                }
                let next_method = redirect_method(&current_method, status);
                let method_changed_to_get =
                    next_method == Method::GET && current_method != Method::GET;
                let same_origin_redirect = same_origin(&current_uri, &next_uri);
                sanitize_headers_for_redirect(
                    &mut current_headers,
                    method_changed_to_get,
                    same_origin_redirect,
                );
                if method_changed_to_get {
                    streaming_body = None;
                }
                current_method = next_method;
                current_uri = next_uri;
                current_redacted_uri = redact_uri_for_logs(&current_uri.to_string());
                redirect_count += 1;
                if max_attempts == 1
                    && body_replayable
                    && self
                        .retry_eligibility
                        .supports_retry(&current_method, &current_headers)
                {
                    max_attempts = retry_policy.max_attempts_value();
                }
                continue;
            }

            if !status.is_success() {
                let Some(read_timeout) =
                    phase_timeout(timeout_value, total_timeout, request_started_at)
                else {
                    let error = deadline_exceeded_error(
                        total_timeout,
                        &current_method,
                        &current_redacted_uri,
                    );
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                let response_body = match timeout(
                    read_timeout,
                    read_all_body_limited(response.into_body(), max_response_body_bytes),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    Ok(Err(ReadBodyError::Read(source))) => {
                        let error = HttpClientError::ReadBody {
                            source: Box::new(source),
                        };
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                    Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                        let error = HttpClientError::ResponseBodyTooLarge {
                            limit_bytes: max_response_body_bytes,
                            actual_bytes,
                            method: current_method.clone(),
                            uri: current_redacted_uri.clone(),
                        };
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                    Err(_) => {
                        let error = HttpClientError::Timeout {
                            phase: TimeoutPhase::ResponseBody,
                            timeout_ms: read_timeout.as_millis(),
                            method: current_method.clone(),
                            uri: current_redacted_uri.clone(),
                        };
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                };
                let response_body = decode_content_encoded_body_limited(
                    response_body,
                    &response_headers,
                    max_response_body_bytes,
                )
                .map_err(|error| {
                    decode_response_body_error(
                        error,
                        max_response_body_bytes,
                        &current_method,
                        &current_redacted_uri,
                    )
                })?;
                self.run_response_interceptors(&context, status, &response_headers);

                let error = HttpClientError::HttpStatus {
                    status: status.as_u16(),
                    method: current_method.clone(),
                    uri: current_redacted_uri.clone(),
                    body: truncate_body(&response_body),
                };
                self.observe_server_throttle(
                    status,
                    &response_headers,
                    rate_limit_host.as_deref(),
                    retry_policy.backoff_for_retry(attempt),
                );
                let retry_decision = RetryDecision {
                    attempt,
                    max_attempts,
                    method: current_method.clone(),
                    uri: current_redacted_uri.clone(),
                    status: Some(status),
                    transport_error_kind: None,
                    timeout_phase: None,
                    response_body_read_error: false,
                };
                if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision) {
                    if let Err(error) =
                        self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                    {
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                    let retry_delay = parse_retry_after(&response_headers, SystemTime::now())
                        .unwrap_or_else(|| retry_policy.backoff_for_retry(attempt));
                    let Some(retry_delay) =
                        bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                    else {
                        let error = deadline_exceeded_error(
                            total_timeout,
                            &current_method,
                            &current_redacted_uri,
                        );
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    };
                    self.metrics.record_retry();
                    if !retry_delay.is_zero() {
                        sleep(retry_delay).await;
                    }
                    attempt += 1;
                    continue;
                }
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            self.run_response_interceptors(&context, status, &response_headers);
            if let Some(attempt_guard) = circuit_attempt.take() {
                attempt_guard.mark_success();
            }
            if let Some(adaptive_guard) = adaptive_attempt.take() {
                adaptive_guard.mark_success();
            }
            self.record_successful_request_for_resilience();

            return Ok(HttpResponseStream::new(
                status,
                response_headers,
                response.into_body(),
                current_method.clone(),
                current_redacted_uri.clone(),
            ));
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

    async fn send_request_with_retry(
        &self,
        method: Method,
        uri: Uri,
        redacted_uri_text: String,
        merged_headers: HeaderMap,
        body: RequestBody,
        execution_options: RequestExecutionOptions,
    ) -> Result<HttpResponse, HttpClientError> {
        let timeout_value = execution_options
            .request_timeout
            .unwrap_or(self.request_timeout)
            .max(Duration::from_millis(1));
        let total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let max_response_body_bytes = execution_options
            .max_response_body_bytes
            .unwrap_or(self.max_response_body_bytes)
            .max(1);
        let (buffered_body, mut streaming_body) = match body {
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
        let mut max_attempts = if self
            .retry_eligibility
            .supports_retry(&method, &merged_headers)
            && body_replayable
        {
            retry_policy.max_attempts_value()
        } else {
            1
        };
        let request_started_at = Instant::now();
        let mut attempt = 1_usize;
        let mut redirect_count = 0_usize;
        let mut current_method = method;
        let mut current_uri = uri;
        let mut current_redacted_uri = redacted_uri_text;
        let mut current_headers = merged_headers;

        while attempt <= max_attempts {
            let span = info_span!(
                "reqx.request",
                client = %self.client_name,
                method = %current_method,
                uri = %current_redacted_uri,
                attempt = attempt,
                max_attempts = max_attempts
            );
            let _enter = span.enter();
            let started = Instant::now();
            let context = RequestContext::new(
                current_method.clone(),
                current_redacted_uri.clone(),
                attempt,
                max_attempts,
                redirect_count,
            );

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
            let mut adaptive_attempt = self.begin_adaptive_attempt().await;
            let mut attempt_headers = current_headers.clone();
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
                    let error = HttpClientError::Transport {
                        kind,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        source: Box::new(source),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: Some(kind),
                        timeout_phase: None,
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        warn!(
                            delay_ms = retry_delay.as_millis() as u64,
                            error = %error,
                            "retrying request after transport error"
                        );
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Err(TransportRequestError::Timeout) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::Transport,
                        timeout_ms: transport_timeout.as_millis(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::Transport),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        warn!(
                            delay_ms = retry_delay.as_millis() as u64,
                            error = %error,
                            "retrying request after timeout"
                        );
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            let status = response.status();
            let mut response_headers = response.headers().clone();
            if redirect_policy.enabled() && is_redirect_status(status) {
                if redirect_count >= redirect_policy.max_redirects() {
                    let error = HttpClientError::RedirectLimitExceeded {
                        max_redirects: redirect_policy.max_redirects(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                if !body_replayable
                    && !matches!(
                        current_method,
                        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                    )
                {
                    let error = HttpClientError::RedirectBodyNotReplayable {
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                let Some(location) = redirect_location(&response_headers) else {
                    let error = HttpClientError::MissingRedirectLocation {
                        status: status.as_u16(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                let Some(next_uri) = resolve_redirect_uri(&current_uri, &location) else {
                    let error = HttpClientError::InvalidRedirectLocation {
                        location,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                self.run_response_interceptors(&context, status, &response_headers);
                if let Some(attempt_guard) = circuit_attempt.take() {
                    attempt_guard.mark_success();
                }
                if let Some(adaptive_guard) = adaptive_attempt.take() {
                    adaptive_guard.mark_success();
                }
                let next_method = redirect_method(&current_method, status);
                let method_changed_to_get =
                    next_method == Method::GET && current_method != Method::GET;
                let same_origin_redirect = same_origin(&current_uri, &next_uri);
                sanitize_headers_for_redirect(
                    &mut current_headers,
                    method_changed_to_get,
                    same_origin_redirect,
                );
                if method_changed_to_get {
                    streaming_body = None;
                }
                current_method = next_method;
                current_uri = next_uri;
                current_redacted_uri = redact_uri_for_logs(&current_uri.to_string());
                redirect_count += 1;
                if max_attempts == 1
                    && body_replayable
                    && self
                        .retry_eligibility
                        .supports_retry(&current_method, &current_headers)
                {
                    max_attempts = retry_policy.max_attempts_value();
                }
                continue;
            }
            let Some(read_timeout) =
                phase_timeout(timeout_value, total_timeout, request_started_at)
            else {
                let error =
                    deadline_exceeded_error(total_timeout, &current_method, &current_redacted_uri);
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };
            let response_body = match timeout(
                read_timeout,
                read_all_body_limited(response.into_body(), max_response_body_bytes),
            )
            .await
            {
                Ok(Ok(body)) => body,
                Ok(Err(ReadBodyError::Read(source))) => {
                    let error = HttpClientError::ReadBody {
                        source: Box::new(source),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: None,
                        response_body_read_error: true,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        warn!(
                            delay_ms = retry_delay.as_millis() as u64,
                            error = %error,
                            "retrying request after response body read error"
                        );
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                    let error = HttpClientError::ResponseBodyTooLarge {
                        limit_bytes: max_response_body_bytes,
                        actual_bytes,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Err(_) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::ResponseBody,
                        timeout_ms: read_timeout.as_millis(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::ResponseBody),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        if let Err(error) =
                            self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                        {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            let error = deadline_exceeded_error(
                                total_timeout,
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        };
                        warn!(
                            delay_ms = retry_delay.as_millis() as u64,
                            error = %error,
                            "retrying request after response body timeout"
                        );
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };
            let response_body = decode_content_encoded_body_limited(
                response_body,
                &response_headers,
                max_response_body_bytes,
            )
            .map_err(|error| {
                decode_response_body_error(
                    error,
                    max_response_body_bytes,
                    &current_method,
                    &current_redacted_uri,
                )
            })?;
            if response_headers.contains_key(CONTENT_ENCODING) {
                remove_content_encoding_headers(&mut response_headers);
            }

            debug!(
                status = status.as_u16(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "request completed"
            );
            self.run_response_interceptors(&context, status, &response_headers);

            if !status.is_success() {
                let error = HttpClientError::HttpStatus {
                    status: status.as_u16(),
                    method: current_method.clone(),
                    uri: current_redacted_uri.clone(),
                    body: truncate_body(&response_body),
                };
                self.observe_server_throttle(
                    status,
                    &response_headers,
                    rate_limit_host.as_deref(),
                    retry_policy.backoff_for_retry(attempt),
                );
                let retry_decision = RetryDecision {
                    attempt,
                    max_attempts,
                    method: current_method.clone(),
                    uri: current_redacted_uri.clone(),
                    status: Some(status),
                    transport_error_kind: None,
                    timeout_phase: None,
                    response_body_read_error: false,
                };
                if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision) {
                    if let Err(error) =
                        self.try_consume_retry_budget(&current_method, &current_redacted_uri)
                    {
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    }
                    let retry_delay = parse_retry_after(&response_headers, SystemTime::now())
                        .unwrap_or_else(|| retry_policy.backoff_for_retry(attempt));
                    let Some(retry_delay) =
                        bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                    else {
                        let error = deadline_exceeded_error(
                            total_timeout,
                            &current_method,
                            &current_redacted_uri,
                        );
                        self.run_error_interceptors(&context, &error);
                        return Err(error);
                    };
                    warn!(
                        status = status.as_u16(),
                        delay_ms = retry_delay.as_millis() as u64,
                        error = %error,
                        "retrying request after retryable status"
                    );
                    self.metrics.record_retry();
                    if !retry_delay.is_zero() {
                        sleep(retry_delay).await;
                    }
                    attempt += 1;
                    continue;
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
            return Ok(HttpResponse::new(status, response_headers, response_body));
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
