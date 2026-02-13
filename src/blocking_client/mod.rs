use std::io::Read;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Uri};

use crate::extensions::{BackoffSource, BodyCodec, Clock, EndpointSelector, OtelPathNormalizer};
use crate::metrics::ClientMetrics;
use crate::observe::Observer;
use crate::policy::{Interceptor, RedirectPolicy, StatusPolicy};
use crate::proxy::{NoProxyRule, ProxyConfig};
use crate::rate_limit::{RateLimitPolicy, RateLimiter, ServerThrottleScope};
use crate::resilience::{
    AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState, CircuitBreaker, CircuitBreakerPolicy,
    RetryBudget, RetryBudgetPolicy,
};
use crate::retry::{RetryEligibility, RetryPolicy};
use crate::tls::{TlsBackend, TlsOptions};
use crate::util::lock_unpoisoned;

mod builder;
mod execute;
mod request;
mod transport;

pub use request::RequestBuilder;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 8;
const DEFAULT_POOL_MAX_IDLE_CONNECTIONS: usize = 16;
const DEFAULT_CLIENT_NAME: &str = "reqx";
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
struct AdaptiveConcurrencyController {
    policy: AdaptiveConcurrencyPolicy,
    state: Mutex<AdaptiveConcurrencyState>,
    condvar: Condvar,
}

impl AdaptiveConcurrencyController {
    fn new(policy: AdaptiveConcurrencyPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(AdaptiveConcurrencyState::new(policy)),
            condvar: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> AdaptiveConcurrencyPermit {
        let mut state = lock_unpoisoned(&self.state);
        while !state.try_acquire() {
            state = match self.condvar.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        drop(state);
        AdaptiveConcurrencyPermit {
            controller: Arc::clone(self),
            started_at: Instant::now(),
            completed: false,
        }
    }

    fn release_and_record(&self, success: bool, latency: Duration) {
        let mut state = lock_unpoisoned(&self.state);
        state.release_and_record(self.policy, success, latency);
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

struct RequestExecutionOptions {
    request_timeout: Option<Duration>,
    total_timeout: Option<Duration>,
    retry_policy: Option<RetryPolicy>,
    max_response_body_bytes: Option<usize>,
    redirect_policy: Option<RedirectPolicy>,
    status_policy: Option<StatusPolicy>,
    auto_accept_encoding: Option<bool>,
}

enum RequestBody {
    Buffered(Bytes),
    Reader(Box<dyn Read + Send>),
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
    pool_max_idle_connections: usize,
    http_proxy: Option<Uri>,
    proxy_authorization: Option<http::HeaderValue>,
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
    metrics_enabled: bool,
    otel_enabled: bool,
    otel_path_normalizer: Arc<dyn OtelPathNormalizer>,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}

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
    tls_backend: TlsBackend,
    transport: transport::TransportAgents,
    proxy_config: Option<ProxyConfig>,
    endpoint_selector: Arc<dyn EndpointSelector>,
    body_codec: Arc<dyn BodyCodec>,
    clock: Arc<dyn Clock>,
    backoff_source: Arc<dyn BackoffSource>,
    connect_timeout: Duration,
    metrics: ClientMetrics,
    interceptors: Vec<Arc<dyn Interceptor>>,
    observers: Vec<Arc<dyn Observer>>,
}
