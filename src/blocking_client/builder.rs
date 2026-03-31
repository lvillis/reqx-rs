use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Uri};

use crate::config::ClientProfile;
use crate::error::Error;
use crate::extensions::{
    BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer, PolicyBackoffSource,
    PrimaryEndpointSelector, StandardBodyCodec, StandardOtelPathNormalizer, SystemClock,
};
use crate::metrics::ClientMetrics;
use crate::observe::Observer;
use crate::otel::OtelTelemetry;
use crate::policy::{Interceptor, RedirectPolicy, StatusPolicy};
use crate::proxy::{NoProxyRule, ProxyConfig, parse_no_proxy_rule, parse_no_proxy_rules};
use crate::rate_limit::{RateLimitPolicy, RateLimiter, ServerThrottleScope};
use crate::resilience::{
    AdaptiveConcurrencyPolicy, CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
};
use crate::response::DEFAULT_STREAM_DEADLINE_SLACK;
use crate::retry::{
    PermissiveRetryEligibility, RetryEligibility, RetryPolicy, StrictRetryEligibility,
};
use crate::tls::{TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore};
use crate::util::{
    parse_header_name, parse_header_value, redact_uri_for_logs, validate_base_url,
    validate_http_proxy_uri,
};

use super::transport::{TransportAgents, backend_is_available, default_tls_backend, make_agent};
use super::{
    AdaptiveConcurrencyController, Client, ClientBuilder, DEFAULT_CLIENT_NAME,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BODY_BYTES, DEFAULT_POOL_IDLE_TIMEOUT,
    DEFAULT_POOL_MAX_IDLE_CONNECTIONS, DEFAULT_POOL_MAX_IDLE_PER_HOST, DEFAULT_REQUEST_TIMEOUT,
    RequestLimiters,
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
            stream_deadline_slack: DEFAULT_STREAM_DEADLINE_SLACK,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            pool_idle_timeout: DEFAULT_POOL_IDLE_TIMEOUT,
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            pool_max_idle_connections: DEFAULT_POOL_MAX_IDLE_CONNECTIONS,
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
    pub fn request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout.max(Duration::from_millis(1));
        self
    }

    /// Sets the overall request deadline, including retries and redirects.
    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        self
    }

    /// Tunes near-deadline classification for streaming body reads.
    ///
    /// This only affects how ambiguous boundary cases are classified between
    /// `Timeout(ResponseBody)` and `DeadlineExceeded` when the total deadline is
    /// already the tighter bound for the current read. The default is a small
    /// 10ms jitter buffer; changing it does not shorten the actual time spent
    /// waiting on the transport's socket timers.
    pub fn stream_deadline_slack(mut self, stream_deadline_slack: Duration) -> Self {
        self.stream_deadline_slack = stream_deadline_slack;
        self
    }

    /// Sets the default buffered response body size limit in bytes.
    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = max_response_body_bytes.max(1);
        self
    }

    /// Sets the connect timeout used before a socket is established.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout.max(Duration::from_millis(1));
        self
    }

    /// Sets how long idle pooled connections may be kept alive.
    pub fn pool_idle_timeout(mut self, pool_idle_timeout: Duration) -> Self {
        self.pool_idle_timeout = pool_idle_timeout.max(Duration::from_millis(1));
        self
    }

    /// Sets the maximum number of idle pooled connections kept per host.
    pub fn pool_max_idle_per_host(mut self, pool_max_idle_per_host: usize) -> Self {
        self.pool_max_idle_per_host = pool_max_idle_per_host.max(1);
        self
    }

    /// Sets the maximum number of idle pooled connections kept in total.
    pub fn pool_max_idle_connections(mut self, pool_max_idle_connections: usize) -> Self {
        self.pool_max_idle_connections = pool_max_idle_connections.max(1);
        self
    }

    /// Routes requests through the given HTTP proxy.
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
                None => self.invalid_no_proxy_rules.push(raw.to_owned()),
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
            self.invalid_no_proxy_rules.push(raw.to_owned());
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
    pub fn tls_backend(mut self, tls_backend: TlsBackend) -> Self {
        self.tls_backend = tls_backend;
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
    /// This does not replace the OS timers used for transport I/O.
    pub fn control_clock_arc(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets the time source used by Retry-After parsing and internal control loops.
    ///
    /// This does not replace the OS timers used for transport I/O.
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
    pub fn tls_root_store(mut self, tls_root_store: TlsRootStore) -> Self {
        self.tls_options.root_store = tls_root_store;
        self
    }

    /// Adds a PEM-encoded root CA certificate.
    pub fn tls_root_ca_pem(mut self, certificate_pem: impl Into<Vec<u8>>) -> Self {
        self.tls_options
            .root_certificates
            .push(TlsRootCertificate::Pem(certificate_pem.into()));
        self
    }

    /// Adds a DER-encoded root CA certificate.
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

    /// Allows retries for methods that are not normally considered idempotent.
    pub fn allow_non_idempotent_retries(mut self, allow: bool) -> Self {
        self.retry_eligibility = if allow {
            Arc::new(PermissiveRetryEligibility)
        } else {
            Arc::new(StrictRetryEligibility)
        };
        self
    }

    /// Sets the client name used in metrics and user-facing diagnostics.
    pub fn client_name(mut self, client_name: impl Into<String>) -> Self {
        self.client_name = client_name.into();
        self
    }

    /// Caps the total number of in-flight requests.
    pub fn max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = Some(max_in_flight.max(1));
        self
    }

    /// Caps the number of in-flight requests per host.
    pub fn max_in_flight_per_host(mut self, max_in_flight_per_host: usize) -> Self {
        self.max_in_flight_per_host = Some(max_in_flight_per_host.max(1));
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
    pub fn build(self) -> crate::Result<Client> {
        validate_base_url(&self.base_url)?;
        if let Some(proxy_uri) = self.http_proxy.as_ref() {
            validate_http_proxy_uri(proxy_uri)?;
        }
        if self.proxy_authorization.is_some() {
            let Some(proxy_uri) = self.http_proxy.as_ref() else {
                return Err(Error::ProxyAuthorizationRequiresHttpProxy);
            };
            let proxy_uri_has_credentials = proxy_uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'));
            if !proxy_uri_has_credentials {
                return Err(Error::InvalidProxyConfig {
                    proxy_uri: redact_uri_for_logs(&proxy_uri.to_string()),
                    message: "blocking proxy_authorization(...) is unsupported for ureq transport; set credentials in http_proxy URI (e.g. http://user:pass@proxy:port)".to_owned(),
                });
            }
        }
        if let Some(rule) = self.invalid_no_proxy_rules.first() {
            return Err(Error::InvalidNoProxyRule { rule: rule.clone() });
        }
        if let Some(policy) = self.adaptive_concurrency_policy {
            policy.validate()?;
        }

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
            let proxy = ureq::Proxy::new(&proxy_config.uri.to_string()).map_err(|_| {
                Error::InvalidProxyConfig {
                    proxy_uri: redact_uri_for_logs(&proxy_config.uri.to_string()),
                    message: "failed to initialize blocking proxy from http_proxy URI".to_owned(),
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
            default_headers: self.default_headers,
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
            tls_backend: self.tls_backend,
            transport: TransportAgents {
                direct,
                proxy: proxied,
            },
            proxy_config,
            endpoint_selector: self.endpoint_selector,
            body_codec: self.body_codec,
            clock: Arc::clone(&clock),
            backoff_source: self.backoff_source,
            connect_timeout: self.connect_timeout,
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
