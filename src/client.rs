use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Response, Uri};
use hyper::body::Incoming;
#[cfg(any(
    feature = "tls-native",
    feature = "tls-rustls-ring",
    feature = "tls-rustls-aws-lc-rs"
))]
use hyper_util::client::legacy::Client;
#[cfg(any(
    feature = "tls-native",
    feature = "tls-rustls-ring",
    feature = "tls-rustls-aws-lc-rs"
))]
use hyper_util::rt::TokioExecutor;
use tokio::time::{sleep, timeout};
use tracing::{debug, info_span, warn};

#[cfg(any(feature = "tls-rustls-ring", feature = "tls-rustls-aws-lc-rs"))]
use hyper_rustls::HttpsConnectorBuilder;

use crate::ReqxResult;
use crate::body::{
    ReadBodyError, ReqBody, RequestBody, buffered_req_body, build_http_request,
    decode_content_encoded_body, empty_req_body, read_all_body_limited,
};
use crate::error::{HttpClientError, TimeoutPhase};
use crate::limiters::{RequestLimiters, RequestPermits};
use crate::metrics::{HttpClientMetrics, HttpClientMetricsSnapshot};
#[cfg(any(
    feature = "tls-native",
    feature = "tls-rustls-ring",
    feature = "tls-rustls-aws-lc-rs"
))]
use crate::proxy::ProxyConnector;
use crate::proxy::{NoProxyRule, ProxyConfig};
use crate::request::RequestBuilder;
use crate::response::{HttpResponse, HttpResponseStream};
use crate::retry::{
    PermissiveRetryEligibility, RetryDecision, RetryEligibility, RetryPolicy,
    StrictRetryEligibility,
};
use crate::util::{
    bounded_retry_delay, classify_transport_error, deadline_exceeded_error, ensure_accept_encoding,
    merge_headers, parse_header_name, parse_header_value, parse_retry_after, phase_timeout,
    redact_uri_for_logs, resolve_uri, truncate_body,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
const DEFAULT_CLIENT_NAME: &str = "reqx";
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsBackend {
    RustlsRing,
    RustlsAwsLcRs,
    NativeTls,
}

impl TlsBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustlsRing => "tls-rustls-ring",
            Self::RustlsAwsLcRs => "tls-rustls-aws-lc-rs",
            Self::NativeTls => "tls-native",
        }
    }
}

const fn default_tls_backend() -> TlsBackend {
    #[cfg(feature = "tls-rustls-ring")]
    {
        return TlsBackend::RustlsRing;
    }
    #[cfg(all(not(feature = "tls-rustls-ring"), feature = "tls-rustls-aws-lc-rs"))]
    {
        return TlsBackend::RustlsAwsLcRs;
    }
    #[cfg(all(
        not(feature = "tls-rustls-ring"),
        not(feature = "tls-rustls-aws-lc-rs"),
        feature = "tls-native"
    ))]
    {
        return TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    TlsBackend::RustlsRing
}

#[cfg(any(feature = "tls-rustls-ring", feature = "tls-rustls-aws-lc-rs"))]
type RustlsHttpsConnector = hyper_rustls::HttpsConnector<ProxyConnector>;
#[cfg(any(feature = "tls-rustls-ring", feature = "tls-rustls-aws-lc-rs"))]
type RustlsHyperClient = Client<RustlsHttpsConnector, ReqBody>;

#[cfg(feature = "tls-native")]
type NativeHttpsConnector = hyper_tls::HttpsConnector<ProxyConnector>;
#[cfg(feature = "tls-native")]
type NativeHyperClient = Client<NativeHttpsConnector, ReqBody>;

#[derive(Clone)]
enum TransportClient {
    #[cfg(any(feature = "tls-rustls-ring", feature = "tls-rustls-aws-lc-rs"))]
    Rustls(RustlsHyperClient),
    #[cfg(feature = "tls-native")]
    Native(NativeHyperClient),
}

impl TransportClient {
    async fn request(
        &self,
        request: Request<ReqBody>,
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        #[cfg(not(any(
            feature = "tls-native",
            feature = "tls-rustls-ring",
            feature = "tls-rustls-aws-lc-rs"
        )))]
        let _ = &request;

        match self {
            #[cfg(any(feature = "tls-rustls-ring", feature = "tls-rustls-aws-lc-rs"))]
            Self::Rustls(client) => client.request(request).await,
            #[cfg(feature = "tls-native")]
            Self::Native(client) => client.request(request).await,
            #[cfg(not(any(
                feature = "tls-native",
                feature = "tls-rustls-ring",
                feature = "tls-rustls-aws-lc-rs"
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

fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

#[cfg(feature = "tls-rustls-ring")]
fn build_rustls_ring_transport(
    proxy_config: Option<ProxyConfig>,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> ReqxResult<TransportClient> {
    let connector = ProxyConnector::new(proxy_config);
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .map_err(|source| HttpClientError::TlsBackendInit {
            backend: TlsBackend::RustlsRing.as_str(),
            message: source.to_string(),
        })?
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

#[cfg(not(feature = "tls-rustls-ring"))]
fn build_rustls_ring_transport(
    _proxy_config: Option<ProxyConfig>,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> ReqxResult<TransportClient> {
    Err(HttpClientError::TlsBackendUnavailable {
        backend: TlsBackend::RustlsRing.as_str(),
    })
}

#[cfg(feature = "tls-rustls-aws-lc-rs")]
fn build_rustls_aws_lc_rs_transport(
    proxy_config: Option<ProxyConfig>,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> ReqxResult<TransportClient> {
    let connector = ProxyConnector::new(proxy_config);
    let https = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|source| HttpClientError::TlsBackendInit {
            backend: TlsBackend::RustlsAwsLcRs.as_str(),
            message: source.to_string(),
        })?
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

#[cfg(not(feature = "tls-rustls-aws-lc-rs"))]
fn build_rustls_aws_lc_rs_transport(
    _proxy_config: Option<ProxyConfig>,
    _pool_idle_timeout: Duration,
    _pool_max_idle_per_host: usize,
    _http2_only: bool,
) -> ReqxResult<TransportClient> {
    Err(HttpClientError::TlsBackendUnavailable {
        backend: TlsBackend::RustlsAwsLcRs.as_str(),
    })
}

#[cfg(feature = "tls-native")]
fn build_native_tls_transport(
    proxy_config: Option<ProxyConfig>,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> ReqxResult<TransportClient> {
    let connector = ProxyConnector::new(proxy_config);
    let https = hyper_tls::HttpsConnector::new_with_connector(connector);
    let transport = Client::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(pool_max_idle_per_host)
        .http2_only(http2_only)
        .build(https);
    Ok(TransportClient::Native(transport))
}

#[cfg(not(feature = "tls-native"))]
fn build_native_tls_transport(
    _proxy_config: Option<ProxyConfig>,
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
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
) -> ReqxResult<TransportClient> {
    match tls_backend {
        TlsBackend::RustlsRing => build_rustls_ring_transport(
            proxy_config,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::RustlsAwsLcRs => build_rustls_aws_lc_rs_transport(
            proxy_config,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
        TlsBackend::NativeTls => build_native_tls_transport(
            proxy_config,
            pool_idle_timeout,
            pool_max_idle_per_host,
            http2_only,
        ),
    }
}

pub(crate) struct RequestExecutionOptions {
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) max_response_body_bytes: Option<usize>,
}

pub struct HttpClientBuilder {
    base_url: String,
    default_headers: HeaderMap,
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    max_response_body_bytes: usize,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    http2_only: bool,
    http_proxy: Option<Uri>,
    proxy_authorization: Option<HeaderValue>,
    no_proxy_rules: Vec<NoProxyRule>,
    retry_policy: RetryPolicy,
    retry_eligibility: Arc<dyn RetryEligibility>,
    tls_backend: TlsBackend,
    client_name: String,
    max_in_flight: Option<usize>,
    max_in_flight_per_host: Option<usize>,
}

impl HttpClientBuilder {
    pub(crate) fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            default_headers: HeaderMap::new(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            total_timeout: None,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            http2_only: false,
            http_proxy: None,
            proxy_authorization: None,
            no_proxy_rules: Vec::new(),
            retry_policy: RetryPolicy::standard(),
            retry_eligibility: Arc::new(StrictRetryEligibility),
            tls_backend: default_tls_backend(),
            client_name: DEFAULT_CLIENT_NAME.to_owned(),
            max_in_flight: None,
            max_in_flight_per_host: None,
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

    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
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

    pub fn try_build(self) -> ReqxResult<HttpClient> {
        let proxy_config = self.http_proxy.map(|uri| ProxyConfig {
            uri,
            authorization: self.proxy_authorization,
            no_proxy_rules: self.no_proxy_rules,
        });
        let transport = build_transport_client(
            self.tls_backend,
            proxy_config,
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            self.http2_only,
        )?;

        Ok(HttpClient {
            base_url: self.base_url,
            default_headers: self.default_headers,
            request_timeout: self.request_timeout,
            total_timeout: self.total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
            retry_eligibility: self.retry_eligibility,
            client_name: self.client_name,
            tls_backend: self.tls_backend,
            transport,
            request_limiters: RequestLimiters::new(self.max_in_flight, self.max_in_flight_per_host),
            metrics: HttpClientMetrics::default(),
        })
    }

    pub fn build(self) -> HttpClient {
        self.try_build()
            .unwrap_or_else(|error| panic!("failed to build reqx http client: {error}"))
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
    client_name: String,
    tls_backend: TlsBackend,
    transport: TransportClient,
    request_limiters: Option<RequestLimiters>,
    metrics: HttpClientMetrics,
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
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let host = uri.host().map(|item| item.to_ascii_lowercase());
        let _permits = match self.acquire_request_permits(host.as_deref()).await {
            Ok(permits) => permits,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
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
        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let host = uri.host().map(|item| item.to_ascii_lowercase());
        let _permits = match self.acquire_request_permits(host.as_deref()).await {
            Ok(permits) => permits,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
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
        let max_attempts = if self
            .retry_eligibility
            .supports_retry(&method, &merged_headers)
            && body_replayable
        {
            retry_policy.max_attempts_value()
        } else {
            1
        };
        let request_started_at = Instant::now();

        for attempt in 1..=max_attempts {
            let span = info_span!(
                "reqx.request.stream",
                client = %self.client_name,
                method = %method,
                uri = %redacted_uri_text,
                attempt = attempt,
                max_attempts = max_attempts
            );
            let _enter = span.enter();
            debug!("sending stream request");

            let Some(transport_timeout) =
                phase_timeout(timeout_value, total_timeout, request_started_at)
            else {
                return Err(deadline_exceeded_error(
                    total_timeout,
                    &method,
                    &redacted_uri_text,
                ));
            };

            let request_body = if let Some(body) = &buffered_body {
                buffered_req_body(body.clone())
            } else {
                streaming_body.take().unwrap_or_else(empty_req_body)
            };
            let request =
                build_http_request(method.clone(), uri.clone(), &merged_headers, request_body)?;
            let response = match self
                .send_transport_request(transport_timeout, request)
                .await
            {
                Ok(response) => response,
                Err(TransportRequestError::Transport(source)) => {
                    let kind = classify_transport_error(&source);
                    let error = HttpClientError::Transport {
                        kind,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        source,
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: Some(kind),
                        timeout_phase: None,
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
                        };
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        continue;
                    }
                    return Err(error);
                }
                Err(TransportRequestError::Timeout) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::Transport,
                        timeout_ms: transport_timeout.as_millis(),
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::Transport),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
                        };
                        self.metrics.record_retry();
                        if !retry_delay.is_zero() {
                            sleep(retry_delay).await;
                        }
                        continue;
                    }
                    return Err(error);
                }
            };

            let status = response.status();
            let response_headers = response.headers().clone();

            if !status.is_success() {
                let Some(read_timeout) =
                    phase_timeout(timeout_value, total_timeout, request_started_at)
                else {
                    return Err(deadline_exceeded_error(
                        total_timeout,
                        &method,
                        &redacted_uri_text,
                    ));
                };
                let response_body = match timeout(
                    read_timeout,
                    read_all_body_limited(response.into_body(), max_response_body_bytes),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    Ok(Err(ReadBodyError::Read(source))) => {
                        return Err(HttpClientError::ReadBody { source });
                    }
                    Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                        return Err(HttpClientError::ResponseBodyTooLarge {
                            limit_bytes: max_response_body_bytes,
                            actual_bytes,
                            method: method.clone(),
                            uri: redacted_uri_text.clone(),
                        });
                    }
                    Err(_) => {
                        return Err(HttpClientError::Timeout {
                            phase: TimeoutPhase::ResponseBody,
                            timeout_ms: read_timeout.as_millis(),
                            method: method.clone(),
                            uri: redacted_uri_text.clone(),
                        });
                    }
                };
                let response_body = decode_content_encoded_body(response_body, &response_headers)
                    .map_err(|(encoding, message)| {
                    decode_content_encoding_error(encoding, message, &method, &redacted_uri_text)
                })?;

                let error = HttpClientError::HttpStatus {
                    status: status.as_u16(),
                    method: method.clone(),
                    uri: redacted_uri_text.clone(),
                    body: truncate_body(&response_body),
                };
                let retry_decision = RetryDecision {
                    attempt,
                    max_attempts,
                    method: method.clone(),
                    uri: redacted_uri_text.clone(),
                    status: Some(status),
                    transport_error_kind: None,
                    timeout_phase: None,
                    response_body_read_error: false,
                };
                if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision) {
                    let retry_delay = parse_retry_after(&response_headers, SystemTime::now())
                        .unwrap_or_else(|| retry_policy.backoff_for_retry(attempt));
                    let Some(retry_delay) =
                        bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                    else {
                        return Err(deadline_exceeded_error(
                            total_timeout,
                            &method,
                            &redacted_uri_text,
                        ));
                    };
                    self.metrics.record_retry();
                    if !retry_delay.is_zero() {
                        sleep(retry_delay).await;
                    }
                    continue;
                }
                return Err(error);
            }

            return Ok(HttpResponseStream::new(
                status,
                response_headers,
                response.into_body(),
            ));
        }

        Err(deadline_exceeded_error(
            total_timeout,
            &method,
            &redacted_uri_text,
        ))
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
        let max_attempts = if self
            .retry_eligibility
            .supports_retry(&method, &merged_headers)
            && body_replayable
        {
            retry_policy.max_attempts_value()
        } else {
            1
        };
        let request_started_at = Instant::now();

        for attempt in 1..=max_attempts {
            let span = info_span!(
                "reqx.request",
                client = %self.client_name,
                method = %method,
                uri = %redacted_uri_text,
                attempt = attempt,
                max_attempts = max_attempts
            );
            let _enter = span.enter();
            let started = Instant::now();

            debug!("sending request");
            let Some(transport_timeout) =
                phase_timeout(timeout_value, total_timeout, request_started_at)
            else {
                return Err(deadline_exceeded_error(
                    total_timeout,
                    &method,
                    &redacted_uri_text,
                ));
            };
            let request_body = if let Some(body) = &buffered_body {
                buffered_req_body(body.clone())
            } else {
                streaming_body.take().unwrap_or_else(empty_req_body)
            };
            let request =
                build_http_request(method.clone(), uri.clone(), &merged_headers, request_body)?;
            let response = match self
                .send_transport_request(transport_timeout, request)
                .await
            {
                Ok(response) => response,
                Err(TransportRequestError::Transport(source)) => {
                    let kind = classify_transport_error(&source);
                    let error = HttpClientError::Transport {
                        kind,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        source,
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: Some(kind),
                        timeout_phase: None,
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
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
                        continue;
                    }
                    return Err(error);
                }
                Err(TransportRequestError::Timeout) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::Transport,
                        timeout_ms: transport_timeout.as_millis(),
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::Transport),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
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
                        continue;
                    }
                    return Err(error);
                }
            };

            let status = response.status();
            let mut response_headers = response.headers().clone();
            let Some(read_timeout) =
                phase_timeout(timeout_value, total_timeout, request_started_at)
            else {
                return Err(deadline_exceeded_error(
                    total_timeout,
                    &method,
                    &redacted_uri_text,
                ));
            };
            let response_body = match timeout(
                read_timeout,
                read_all_body_limited(response.into_body(), max_response_body_bytes),
            )
            .await
            {
                Ok(Ok(body)) => body,
                Ok(Err(ReadBodyError::Read(source))) => {
                    let error = HttpClientError::ReadBody { source };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: None,
                        response_body_read_error: true,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
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
                        continue;
                    }
                    return Err(error);
                }
                Ok(Err(ReadBodyError::TooLarge { actual_bytes })) => {
                    return Err(HttpClientError::ResponseBodyTooLarge {
                        limit_bytes: max_response_body_bytes,
                        actual_bytes,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                    });
                }
                Err(_) => {
                    let error = HttpClientError::Timeout {
                        phase: TimeoutPhase::ResponseBody,
                        timeout_ms: read_timeout.as_millis(),
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                    };
                    let retry_decision = RetryDecision {
                        attempt,
                        max_attempts,
                        method: method.clone(),
                        uri: redacted_uri_text.clone(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(TimeoutPhase::ResponseBody),
                        response_body_read_error: false,
                    };
                    if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision)
                    {
                        let retry_delay = retry_policy.backoff_for_retry(attempt);
                        let Some(retry_delay) =
                            bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                        else {
                            return Err(deadline_exceeded_error(
                                total_timeout,
                                &method,
                                &redacted_uri_text,
                            ));
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
                        continue;
                    }
                    return Err(error);
                }
            };
            let response_body = decode_content_encoded_body(response_body, &response_headers)
                .map_err(|(encoding, message)| {
                    decode_content_encoding_error(encoding, message, &method, &redacted_uri_text)
                })?;
            if response_headers.contains_key(CONTENT_ENCODING) {
                remove_content_encoding_headers(&mut response_headers);
            }

            debug!(
                status = status.as_u16(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "request completed"
            );

            if !status.is_success() {
                let error = HttpClientError::HttpStatus {
                    status: status.as_u16(),
                    method: method.clone(),
                    uri: redacted_uri_text.clone(),
                    body: truncate_body(&response_body),
                };
                let retry_decision = RetryDecision {
                    attempt,
                    max_attempts,
                    method: method.clone(),
                    uri: redacted_uri_text.clone(),
                    status: Some(status),
                    transport_error_kind: None,
                    timeout_phase: None,
                    response_body_read_error: false,
                };
                if attempt < max_attempts && retry_policy.should_retry_decision(&retry_decision) {
                    let retry_delay = parse_retry_after(&response_headers, SystemTime::now())
                        .unwrap_or_else(|| retry_policy.backoff_for_retry(attempt));
                    let Some(retry_delay) =
                        bounded_retry_delay(retry_delay, total_timeout, request_started_at)
                    else {
                        return Err(deadline_exceeded_error(
                            total_timeout,
                            &method,
                            &redacted_uri_text,
                        ));
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
                    continue;
                }
                return Err(error);
            }

            return Ok(HttpResponse::new(status, response_headers, response_body));
        }

        Err(deadline_exceeded_error(
            total_timeout,
            &method,
            &redacted_uri_text,
        ))
    }
}
