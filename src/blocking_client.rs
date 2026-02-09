use std::io::Read;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Uri};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::IDEMPOTENCY_KEY_HEADER;
use crate::ReqxResult;
use crate::error::{HttpClientError, TimeoutPhase, TransportErrorKind};
use crate::metrics::{HttpClientMetrics, HttpClientMetricsSnapshot};
use crate::policy::{HttpInterceptor, RedirectPolicy, RequestContext};
use crate::proxy::{NoProxyRule, ProxyConfig};
use crate::rate_limit::{RateLimitPolicy, RateLimiter};
use crate::resilience::{
    AdaptiveConcurrencyPolicy, CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
};
use crate::response::HttpResponse;
use crate::retry::{
    PermissiveRetryEligibility, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
use crate::tls::{TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, tls_config_error};
use crate::util::{
    append_query_pairs, bounded_retry_delay, deadline_exceeded_error, ensure_accept_encoding,
    is_redirect_status, lock_unpoisoned, merge_headers, parse_header_name, parse_header_value,
    parse_retry_after, phase_timeout, redact_uri_for_logs, redirect_location, redirect_method,
    resolve_redirect_uri, resolve_uri, same_origin, sanitize_headers_for_redirect, truncate_body,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
const DEFAULT_POOL_MAX_IDLE_CONNECTIONS: usize = 16;
const DEFAULT_CLIENT_NAME: &str = "reqx";
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

const fn default_tls_backend() -> TlsBackend {
    #[cfg(feature = "blocking-tls-rustls-ring")]
    {
        return TlsBackend::RustlsRing;
    }
    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        feature = "blocking-tls-rustls-aws-lc-rs"
    ))]
    {
        return TlsBackend::RustlsAwsLcRs;
    }
    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        not(feature = "blocking-tls-rustls-aws-lc-rs"),
        feature = "blocking-tls-native"
    ))]
    {
        return TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    TlsBackend::RustlsRing
}

fn backend_is_available(backend: TlsBackend) -> bool {
    match backend {
        TlsBackend::RustlsRing => cfg!(feature = "blocking-tls-rustls-ring"),
        TlsBackend::RustlsAwsLcRs => cfg!(feature = "blocking-tls-rustls-aws-lc-rs"),
        TlsBackend::NativeTls => cfg!(feature = "blocking-tls-native"),
    }
}

fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

fn is_proxy_bypassed(proxy: &ProxyConfig, uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    proxy.no_proxy_rules.iter().any(|rule| rule.matches(&host))
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn parse_pem_certificates(
    backend: TlsBackend,
    pem_bundle: &[u8],
    context: &str,
) -> ReqxResult<Vec<ureq::tls::Certificate<'static>>> {
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(pem_bundle) {
        match item.map_err(|source| {
            tls_config_error(backend, format!("failed to parse PEM {context}: {source}"))
        })? {
            ureq::tls::PemItem::Certificate(certificate) => certificates.push(certificate),
            ureq::tls::PemItem::PrivateKey(_) => {}
            _ => {}
        }
    }
    if certificates.is_empty() {
        return Err(tls_config_error(
            backend,
            format!("no certificate blocks found in PEM {context}"),
        ));
    }
    Ok(certificates)
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn build_sync_tls_config(
    backend: TlsBackend,
    tls_options: &TlsOptions,
) -> ReqxResult<ureq::tls::TlsConfig> {
    let provider = match backend {
        TlsBackend::RustlsRing | TlsBackend::RustlsAwsLcRs => ureq::tls::TlsProvider::Rustls,
        TlsBackend::NativeTls => ureq::tls::TlsProvider::NativeTls,
    };

    let mut tls_config_builder = ureq::tls::TlsConfig::builder().provider(provider);

    if !tls_options.root_certificates.is_empty() {
        let mut roots = Vec::new();
        for root_certificate in &tls_options.root_certificates {
            match root_certificate {
                TlsRootCertificate::Pem(pem) => {
                    roots.extend(parse_pem_certificates(backend, pem, "root certificate")?);
                }
                TlsRootCertificate::Der(der) => {
                    roots.push(ureq::tls::Certificate::from_der(der).to_owned());
                }
            }
        }
        tls_config_builder =
            tls_config_builder.root_certs(ureq::tls::RootCerts::new_with_certs(&roots));
    }

    if let Some(identity) = &tls_options.client_identity {
        let client_cert = match identity {
            TlsClientIdentity::Pem {
                cert_chain_pem,
                private_key_pem,
            } => {
                let cert_chain =
                    parse_pem_certificates(backend, cert_chain_pem, "mTLS certificate chain")?;
                let private_key =
                    ureq::tls::PrivateKey::from_pem(private_key_pem).map_err(|source| {
                        tls_config_error(
                            backend,
                            format!("failed to parse mTLS private key PEM: {source}"),
                        )
                    })?;
                ureq::tls::ClientCert::new_with_certs(&cert_chain, private_key)
            }
            TlsClientIdentity::Pkcs12 {
                identity_der,
                password,
            } => {
                return Err(tls_config_error(
                    backend,
                    format!(
                        "PKCS#12 identity is unsupported in sync ureq transport; use PEM cert+key (pkcs12_bytes={}, password_len={})",
                        identity_der.len(),
                        password.len(),
                    ),
                ));
            }
        };
        tls_config_builder = tls_config_builder.client_cert(Some(client_cert));
    }

    #[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
    if backend == TlsBackend::RustlsAwsLcRs {
        tls_config_builder = tls_config_builder.unversioned_rustls_crypto_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ));
    }

    Ok(tls_config_builder.build())
}

#[cfg(not(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
)))]
fn build_sync_tls_config(
    _backend: TlsBackend,
    _tls_options: &TlsOptions,
) -> ReqxResult<ureq::tls::TlsConfig> {
    unreachable!("sync client is not compiled without sync TLS features")
}

fn make_agent(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
    client_name: &str,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_max_idle_connections: usize,
    proxy: Option<ureq::Proxy>,
) -> ReqxResult<ureq::Agent> {
    let tls_config = build_sync_tls_config(tls_backend, tls_options)?;
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .user_agent(client_name)
        .max_idle_age(pool_idle_timeout)
        .max_idle_connections_per_host(pool_max_idle_per_host)
        .max_idle_connections(pool_max_idle_connections)
        .tls_config(tls_config)
        .proxy(proxy)
        .build();
    Ok(config.new_agent())
}

#[derive(Clone)]
struct TransportAgents {
    direct: ureq::Agent,
    proxy: Option<ureq::Agent>,
}

fn ureq_timeout_phase(timeout: ureq::Timeout) -> TimeoutPhase {
    match timeout {
        ureq::Timeout::RecvBody => TimeoutPhase::ResponseBody,
        _ => TimeoutPhase::Transport,
    }
}

fn classify_ureq_transport_error(error: &ureq::Error) -> TransportErrorKind {
    match error {
        ureq::Error::HostNotFound => TransportErrorKind::Dns,
        ureq::Error::Tls(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs"
        ))]
        ureq::Error::Rustls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::NativeTls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::Der(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-native"
        ))]
        ureq::Error::Pem(_) => TransportErrorKind::Tls,
        ureq::Error::ConnectProxyFailed(_) | ureq::Error::ConnectionFailed => {
            TransportErrorKind::Connect
        }
        ureq::Error::Io(source) => match source.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                TransportErrorKind::Read
            }
            std::io::ErrorKind::NotFound => TransportErrorKind::Dns,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrNotAvailable => TransportErrorKind::Connect,
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => TransportErrorKind::Read,
            _ => TransportErrorKind::Other,
        },
        _ => TransportErrorKind::Other,
    }
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

fn wrapped_ureq_error(io_error: &std::io::Error) -> Option<&ureq::Error> {
    io_error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
}

enum ReadBodyError {
    Read(std::io::Error),
    TooLarge { actual_bytes: usize },
}

fn read_all_body_limited(
    response: &mut ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut reader = response.body_mut().as_reader();
    let mut collected = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut total_len = 0_usize;

    loop {
        let read = reader.read(&mut chunk).map_err(ReadBodyError::Read)?;
        if read == 0 {
            break;
        }
        total_len = total_len.saturating_add(read);
        if total_len > max_bytes {
            return Err(ReadBodyError::TooLarge {
                actual_bytes: total_len,
            });
        }
        collected.extend_from_slice(&chunk[..read]);
    }

    Ok(Bytes::from(collected))
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
    condvar: Condvar,
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
            condvar: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        let mut state = lock_unpoisoned(&self.state);
        while state.in_flight >= state.current_limit {
            state = match self.condvar.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        state.in_flight = state.in_flight.saturating_add(1);
        drop(state);
        AdaptiveConcurrencyPermit {
            controller: Arc::clone(self),
            started_at: Instant::now(),
            completed: false,
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

        self.condvar.notify_all();
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

enum RequestBody {
    Buffered(Bytes),
    Reader(Box<dyn Read + Send + Sync>),
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
    pool_max_idle_connections: usize,
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
    redirect_policy: RedirectPolicy,
    tls_backend: TlsBackend,
    tls_options: TlsOptions,
    client_name: String,
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
            pool_max_idle_connections: DEFAULT_POOL_MAX_IDLE_CONNECTIONS,
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
            redirect_policy: RedirectPolicy::none(),
            tls_backend: default_tls_backend(),
            tls_options: TlsOptions::default(),
            client_name: DEFAULT_CLIENT_NAME.to_owned(),
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

    pub fn pool_max_idle_connections(mut self, pool_max_idle_connections: usize) -> Self {
        self.pool_max_idle_connections = pool_max_idle_connections.max(1);
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

    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
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
        if !backend_is_available(self.tls_backend) {
            return Err(HttpClientError::TlsBackendUnavailable {
                backend: self.tls_backend.as_str(),
            });
        }

        let proxy_config = self.http_proxy.map(|uri| ProxyConfig {
            uri,
            authorization: self.proxy_authorization,
            no_proxy_rules: self.no_proxy_rules,
        });

        let direct = make_agent(
            self.tls_backend,
            &self.tls_options,
            &self.client_name,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.pool_max_idle_connections,
            None,
        )?;

        let proxied = if let Some(proxy_config) = &proxy_config {
            let proxy = ureq::Proxy::new(&proxy_config.uri.to_string()).map_err(|_| {
                HttpClientError::InvalidUri {
                    uri: proxy_config.uri.to_string(),
                }
            })?;

            Some(make_agent(
                self.tls_backend,
                &self.tls_options,
                &self.client_name,
                self.pool_idle_timeout,
                self.pool_max_idle_per_host,
                self.pool_max_idle_connections,
                Some(proxy),
            )?)
        } else {
            None
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
            redirect_policy: self.redirect_policy,
            tls_backend: self.tls_backend,
            transport: TransportAgents {
                direct,
                proxy: proxied,
            },
            proxy_config,
            connect_timeout: self.connect_timeout,
            metrics: HttpClientMetrics::default(),
            interceptors: self.interceptors,
        })
    }

    pub fn build(self) -> HttpClient {
        self.try_build()
            .unwrap_or_else(|error| panic!("failed to build reqx blocking http client: {error}"))
    }
}

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
    redirect_policy: RedirectPolicy,
    tls_backend: TlsBackend,
    transport: TransportAgents,
    proxy_config: Option<ProxyConfig>,
    connect_timeout: Duration,
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

    fn begin_adaptive_attempt(&self) -> Option<AdaptiveConcurrencyPermit> {
        let controller = self.adaptive_concurrency.as_ref()?;
        Some(controller.acquire())
    }

    fn acquire_rate_limit_slot(
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
            sleep(wait);
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
        rate_limiter.observe_server_throttle(host, throttle_delay);
    }

    fn select_agent(&self, uri: &Uri) -> (&ureq::Agent, bool) {
        if let Some(proxy_config) = &self.proxy_config
            && !is_proxy_bypassed(proxy_config, uri)
            && let Some(proxy) = &self.transport.proxy
        {
            return (proxy, true);
        }
        (&self.transport.direct, false)
    }

    fn run_once(
        &self,
        method: Method,
        uri: &Uri,
        uri_text: &str,
        headers: &HeaderMap,
        request_body: RequestBody,
        timeout_value: Duration,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpClientError> {
        let (agent, using_proxy) = self.select_agent(uri);
        match request_body {
            RequestBody::Buffered(body) => {
                let mut builder = ureq::http::Request::builder()
                    .method(method.clone())
                    .uri(uri_text);
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                let request = builder
                    .body(body.to_vec())
                    .map_err(|source| HttpClientError::RequestBuild { source })?;
                self.run_configured_request(
                    agent,
                    using_proxy,
                    request,
                    timeout_value,
                    method,
                    uri_text,
                )
            }
            RequestBody::Reader(reader) => {
                let mut builder = ureq::http::Request::builder()
                    .method(method.clone())
                    .uri(uri_text);
                for (name, value) in headers {
                    builder = builder.header(name, value);
                }
                let request = builder
                    .body(ureq::SendBody::from_owned_reader(reader))
                    .map_err(|source| HttpClientError::RequestBuild { source })?;
                self.run_configured_request(
                    agent,
                    using_proxy,
                    request,
                    timeout_value,
                    method,
                    uri_text,
                )
            }
        }
    }

    fn run_configured_request<S: ureq::AsSendBody>(
        &self,
        agent: &ureq::Agent,
        using_proxy: bool,
        request: ureq::http::Request<S>,
        timeout_value: Duration,
        method: Method,
        uri_text: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, HttpClientError> {
        let mut configured_request = agent
            .configure_request(request)
            .timeout_global(Some(timeout_value))
            .timeout_per_call(Some(timeout_value))
            .timeout_connect(Some(self.connect_timeout))
            .timeout_recv_response(Some(timeout_value))
            .timeout_recv_body(Some(timeout_value))
            .build();

        if using_proxy
            && let Some(proxy_config) = &self.proxy_config
            && let Some(proxy_authorization) = &proxy_config.authorization
        {
            configured_request
                .headers_mut()
                .insert("proxy-authorization", proxy_authorization.clone());
        }

        agent
            .run(configured_request)
            .map_err(|source| match source {
                ureq::Error::Timeout(_) => HttpClientError::Timeout {
                    phase: TimeoutPhase::Transport,
                    timeout_ms: timeout_value.as_millis(),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                },
                other => HttpClientError::Transport {
                    kind: classify_ureq_transport_error(&other),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                    source: Box::new(other),
                },
            })
    }

    fn send_request(
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

        let body = body.unwrap_or_else(|| RequestBody::Buffered(Bytes::new()));

        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();

        let result = self.send_request_with_retry(
            method,
            uri,
            redacted_uri_text,
            merged_headers,
            body,
            execution_options,
        );

        self.metrics
            .record_request_completed(&result, request_started_at.elapsed());
        result
    }

    fn send_request_with_retry(
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

        let (buffered_body, mut reader_body) = match body {
            RequestBody::Buffered(body) => (Some(body), None),
            RequestBody::Reader(reader) => (None, Some(reader)),
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
            let context = RequestContext::new(
                current_method.clone(),
                current_redacted_uri.clone(),
                attempt,
                max_attempts,
                redirect_count,
            );
            if let Err(error) = self.acquire_rate_limit_slot(
                current_uri.host(),
                total_timeout,
                request_started_at,
                &current_method,
                &current_redacted_uri,
            ) {
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
            let mut adaptive_attempt = self.begin_adaptive_attempt();

            let request_body = if let Some(body) = &buffered_body {
                RequestBody::Buffered(body.clone())
            } else {
                match reader_body.take() {
                    Some(reader) => RequestBody::Reader(reader),
                    None => RequestBody::Buffered(Bytes::new()),
                }
            };
            let mut attempt_headers = current_headers.clone();
            self.run_request_interceptors(&context, &mut attempt_headers);
            let current_uri_text = current_uri.to_string();

            let mut response = match self.run_once(
                current_method.clone(),
                &current_uri,
                &current_uri_text,
                &attempt_headers,
                request_body,
                transport_timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    let retry_decision = match &error {
                        HttpClientError::Transport { kind, .. } => RetryDecision {
                            attempt,
                            max_attempts,
                            method: current_method.clone(),
                            uri: current_redacted_uri.clone(),
                            status: None,
                            transport_error_kind: Some(*kind),
                            timeout_phase: None,
                            response_body_read_error: false,
                        },
                        HttpClientError::Timeout { phase, .. } => RetryDecision {
                            attempt,
                            max_attempts,
                            method: current_method.clone(),
                            uri: current_redacted_uri.clone(),
                            status: None,
                            transport_error_kind: None,
                            timeout_phase: Some(*phase),
                            response_body_read_error: false,
                        },
                        _ => {
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
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
                            sleep(retry_delay);
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
                    reader_body = None;
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

            let response_body = match read_all_body_limited(&mut response, max_response_body_bytes)
            {
                Ok(body) => body,
                Err(ReadBodyError::TooLarge { actual_bytes }) => {
                    let error = HttpClientError::ResponseBodyTooLarge {
                        limit_bytes: max_response_body_bytes,
                        actual_bytes,
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                Err(ReadBodyError::Read(source)) => {
                    if let Some(ureq_error) = wrapped_ureq_error(&source) {
                        if let ureq::Error::Timeout(timeout) = ureq_error {
                            let timeout_phase = ureq_timeout_phase(*timeout);
                            let error = HttpClientError::Timeout {
                                phase: timeout_phase,
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
                                timeout_phase: Some(timeout_phase),
                                response_body_read_error: false,
                            };
                            if attempt < max_attempts
                                && retry_policy.should_retry_decision(&retry_decision)
                            {
                                if let Err(error) = self.try_consume_retry_budget(
                                    &current_method,
                                    &current_redacted_uri,
                                ) {
                                    self.run_error_interceptors(&context, &error);
                                    return Err(error);
                                }
                                let retry_delay = retry_policy.backoff_for_retry(attempt);
                                let Some(retry_delay) = bounded_retry_delay(
                                    retry_delay,
                                    total_timeout,
                                    request_started_at,
                                ) else {
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
                                    sleep(retry_delay);
                                }
                                attempt += 1;
                                continue;
                            }
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }

                        #[cfg(any(
                            feature = "blocking-tls-rustls-ring",
                            feature = "blocking-tls-rustls-aws-lc-rs",
                            feature = "blocking-tls-native"
                        ))]
                        if let ureq::Error::Decompress(encoding, decode_error) = ureq_error {
                            let error = decode_content_encoding_error(
                                encoding.to_string(),
                                decode_error.to_string(),
                                &current_method,
                                &current_redacted_uri,
                            );
                            self.run_error_interceptors(&context, &error);
                            return Err(error);
                        }
                    }

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
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay);
                        }
                        attempt += 1;
                        continue;
                    }
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
            };

            if response_headers.contains_key(CONTENT_ENCODING) {
                remove_content_encoding_headers(&mut response_headers);
            }
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
                    current_uri.host(),
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
                        sleep(retry_delay);
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

#[doc(hidden)]
pub struct RequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    path: String,
    query_pairs: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<RequestBody>,
    timeout: Option<Duration>,
    total_timeout: Option<Duration>,
    max_response_body_bytes: Option<usize>,
    retry_policy: Option<RetryPolicy>,
    redirect_policy: Option<RedirectPolicy>,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a HttpClient, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            query_pairs: Vec::new(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            total_timeout: None,
            max_response_body_bytes: None,
            retry_policy: None,
            redirect_policy: None,
        }
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn try_header(self, name: &str, value: &str) -> ReqxResult<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.header(name, value))
    }

    pub fn idempotency_key(self, key: &str) -> ReqxResult<Self> {
        self.try_header(IDEMPOTENCY_KEY_HEADER, key)
    }

    pub fn query_pair(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_pairs.push((name.into(), value.into()));
        self
    }

    pub fn query_pairs<K, V, I>(mut self, pairs: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.query_pairs.extend(
            pairs
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    pub fn query<T>(mut self, params: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(params)
            .map_err(|source| crate::error::HttpClientError::SerializeQuery { source })?;
        self.query_pairs.extend(
            url::form_urlencoded::parse(encoded.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned())),
        );
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(RequestBody::Buffered(body.into()));
        self
    }

    pub fn body_reader<R>(mut self, reader: R) -> Self
    where
        R: Read + Send + Sync + 'static,
    {
        self.body = Some(RequestBody::Reader(Box::new(reader)));
        self
    }

    pub fn body_bytes(mut self, body: Bytes) -> Self {
        self.body = Some(RequestBody::Buffered(body));
        self
    }

    pub fn json<T>(self, payload: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let body = serde_json::to_vec(payload)
            .map_err(|source| crate::error::HttpClientError::Serialize { source })?;
        let with_body = self.body_bytes(Bytes::from(body));
        Ok(with_body.header(CONTENT_TYPE, HeaderValue::from_static("application/json")))
    }

    pub fn form<T>(self, payload: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(payload)
            .map_err(|source| crate::error::HttpClientError::SerializeForm { source })?;
        let with_body = self.body_bytes(Bytes::from(encoded));
        Ok(with_body.header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ))
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = Some(max_response_body_bytes.max(1));
        self
    }

    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = Some(retry_policy);
        self
    }

    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = Some(redirect_policy);
        self
    }

    pub fn send(self) -> ReqxResult<HttpResponse> {
        let path = append_query_pairs(&self.path, &self.query_pairs);
        let execution_options = RequestExecutionOptions {
            request_timeout: self.timeout,
            total_timeout: self.total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
            redirect_policy: self.redirect_policy,
        };
        self.client.send_request(
            self.method,
            path,
            self.headers,
            self.body,
            execution_options,
        )
    }

    pub fn send_json<T>(self) -> ReqxResult<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send()?;
        response.json()
    }
}
