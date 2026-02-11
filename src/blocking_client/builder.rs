use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Uri};

use crate::error::Error;
use crate::metrics::ClientMetrics;
use crate::otel::OtelTelemetry;
use crate::policy::{Interceptor, RedirectPolicy, StatusPolicy};
use crate::proxy::{NoProxyRule, ProxyConfig};
use crate::rate_limit::{RateLimitPolicy, RateLimiter, ServerThrottleScope};
use crate::resilience::{
    AdaptiveConcurrencyPolicy, CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
};
use crate::retry::{
    PermissiveRetryEligibility, RetryEligibility, RetryPolicy, StrictRetryEligibility,
};
use crate::tls::{TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore};
use crate::util::{parse_header_name, parse_header_value, validate_base_url};
use crate::{AdvancedConfig, ClientProfile};
use crate::{BackoffSource, BodyCodec, Clock, EndpointSelector, Observer};
use crate::{PolicyBackoffSource, PrimaryEndpointSelector, StandardBodyCodec, SystemClock};

use super::transport::{TransportAgents, backend_is_available, default_tls_backend, make_agent};
use super::{
    AdaptiveConcurrencyController, Client, ClientBuilder, DEFAULT_CLIENT_NAME,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BODY_BYTES, DEFAULT_POOL_IDLE_TIMEOUT,
    DEFAULT_POOL_MAX_IDLE_CONNECTIONS, DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_REQUEST_TIMEOUT,
};

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
            metrics_enabled: false,
            otel_enabled: false,
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

    pub fn try_proxy_authorization(self, proxy_authorization: &str) -> crate::Result<Self> {
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

    pub fn metrics_enabled(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    pub fn otel_enabled(mut self, enabled: bool) -> Self {
        self.otel_enabled = enabled;
        self
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

        if !backend_is_available(self.tls_backend) {
            return Err(Error::TlsBackendUnavailable {
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
            let proxy =
                ureq::Proxy::new(&proxy_config.uri.to_string()).map_err(|_| Error::InvalidUri {
                    uri: proxy_config.uri.to_string(),
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
        let otel = if self.otel_enabled {
            OtelTelemetry::enabled(self.client_name.clone())
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
            tls_backend: self.tls_backend,
            transport: TransportAgents {
                direct,
                proxy: proxied,
            },
            proxy_config,
            endpoint_selector: self.endpoint_selector,
            body_codec: self.body_codec,
            clock: self.clock,
            backoff_source: self.backoff_source,
            connect_timeout: self.connect_timeout,
            metrics: ClientMetrics::with_options(self.metrics_enabled, otel),
            interceptors: self.interceptors,
            observers: self.observers,
        })
    }
}
