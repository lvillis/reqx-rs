use std::thread::sleep;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

use crate::config::RequestTimeoutConfig;
use crate::content_encoding::should_decode_content_encoded_body;
use crate::error::{Error, TimeoutPhase, TransportErrorKind, transport_error};
use crate::execution::{
    AttemptGuards, BodyReadFailure, BodyReadOutcome, BodyReadRetryContext, RequestCompletion,
    RequestExecutionState, RequestExecutionStateInput, ResponseMode, ResponseProgress,
    RetryAttemptState, RetryRequestInput, RetrySchedule, TransportFailurePlan, select_base_url,
    server_throttle_delay,
};
use crate::metrics::MetricsSnapshot;
use crate::policy::{RequestContext, StatusPolicy};
use crate::rate_limit::{resolve_server_throttle_scope, server_throttle_scope_from_headers};
use crate::response::{
    BlockingResponseStream, BlockingResponseStreamContext, Response, StreamLifecycle,
};
use crate::retry::RetryDecision;
use crate::tls::TlsBackend;
use crate::util::{
    bounded_retry_delay, deadline_exceeded_error, ensure_accept_encoding_blocking,
    is_timeout_io_error, merge_headers, redact_uri_for_logs, resolve_uri, total_timeout_deadline,
};

use super::limiters::{AcquirePermitError, GlobalRequestPermit, HostRequestPermit};
use super::transport::{
    ReadBodyError, classify_ureq_transport_error, is_proxy_bypassed, read_all_body_limited,
    remove_content_encoding_headers,
};
use super::{
    AdaptiveConcurrencyPermit, Client, ClientBuilder, RequestBody, RequestBuilder,
    RequestExecutionOptions,
};

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

enum RetryResponse {
    Buffered(Response),
    Stream(Box<BlockingResponseStream>),
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

struct StreamResponseInput {
    status: http::StatusCode,
    response_headers: HeaderMap,
    response_body: ureq::Body,
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
    response_body: ureq::Body,
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
    RetryResponse::Stream(Box::new(BlockingResponseStream::new(
        status,
        response_headers,
        response_body,
        BlockingResponseStreamContext {
            method,
            uri_raw: uri.to_string(),
            uri_redacted: redacted_uri,
            timeout_ms: transport_timeout.as_millis(),
            total_timeout_ms: stream_total_timeout_ms,
            deadline_at: stream_deadline_at,
            deadline_slack: stream_deadline_slack,
            lifecycle: stream_lifecycle,
            global_permit: stream_global_permit,
            host_permit: Some(host_permit),
        },
    )))
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
        scope: crate::rate_limit::ServerThrottleScope,
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

    fn begin_adaptive_attempt(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<Option<AdaptiveConcurrencyPermit>, Error> {
        let Some(controller) = self.adaptive_concurrency.as_ref() else {
            return Ok(None);
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        match controller.acquire(deadline_at) {
            Some(permit) => Ok(Some(permit)),
            None => Err(deadline_exceeded_error(total_timeout, method, uri)),
        }
    }

    fn acquire_global_request_permit(
        &self,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<GlobalRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(GlobalRequestPermit::none());
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        limiters
            .acquire_global(deadline_at)
            .map_err(|AcquirePermitError::Timeout| {
                deadline_exceeded_error(total_timeout, method, uri)
            })
    }

    fn acquire_host_request_permit(
        &self,
        host: Option<&str>,
        total_timeout: Option<Duration>,
        request_started_at: Instant,
        method: &Method,
        uri: &str,
    ) -> Result<HostRequestPermit, Error> {
        let Some(limiters) = &self.request_limiters else {
            return Ok(HostRequestPermit::none());
        };
        let deadline_at = total_timeout_deadline(total_timeout, request_started_at);
        limiters
            .acquire_host(host, deadline_at)
            .map_err(|AcquirePermitError::Timeout| {
                deadline_exceeded_error(total_timeout, method, uri)
            })
    }

    fn acquire_rate_limit_slot(
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
            sleep(wait);
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

    fn prepare_retry(
        &self,
        retry_attempt: RetryAttemptState<'_>,
        context: &RequestContext,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
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

        self.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        Ok(RetrySchedule::Scheduled { delay: retry_delay })
    }

    fn prepare_status_retry(
        &self,
        state: &mut RequestExecutionState,
        context: &RequestContext,
        status: http::StatusCode,
        response_headers: &HeaderMap,
    ) -> Result<RetrySchedule, Error> {
        let retry_plan = state.status_retry_plan(
            status,
            response_headers,
            self.clock.as_ref(),
            self.backoff_source.as_ref(),
        );
        self.prepare_retry(
            state.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
        )
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

    fn handle_body_read_failure(
        &self,
        retry_context: &mut BodyReadRetryContext<'_>,
        failure: BodyReadFailure,
    ) -> Result<BodyReadOutcome, Error> {
        let (error, retry_plan) = match failure {
            BodyReadFailure::Terminal { error } => {
                self.run_error_interceptors(retry_context.context(), &error);
                return Err(error);
            }
            BodyReadFailure::Retryable { error, retry_plan } => (error, retry_plan),
        };

        let context = retry_context.context();
        match self.prepare_retry(
            retry_context.retry_attempt(),
            context,
            &retry_plan.decision,
            retry_plan.delay,
        )? {
            RetrySchedule::Scheduled { delay } => return Ok(BodyReadOutcome::Retry(delay)),
            RetrySchedule::NotScheduled => {}
        }
        self.run_error_interceptors(context, &error);
        Err(error)
    }

    fn read_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        mut retry_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        match read_all_body_limited(response, retry_context.max_response_body_bytes()) {
            Ok(body) => Ok(BodyReadOutcome::Body(body)),
            Err(ReadBodyError::TooLarge { actual_bytes }) => {
                let error = retry_context.response_body_too_large_error(actual_bytes);
                self.run_error_interceptors(retry_context.context(), &error);
                Err(error)
            }
            Err(ReadBodyError::Read(source)) => {
                if is_timeout_io_error(&source) {
                    let failure =
                        retry_context.response_body_timeout_failure(self.backoff_source.as_ref());
                    return self.handle_body_read_failure(&mut retry_context, failure);
                }

                let failure =
                    retry_context.response_body_read_failure(source, self.backoff_source.as_ref());
                self.handle_body_read_failure(&mut retry_context, failure)
            }
        }
    }

    fn read_decoded_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        retry_context: BodyReadRetryContext<'_>,
    ) -> Result<BodyReadOutcome, Error> {
        let max_response_body_bytes = retry_context.max_response_body_bytes();
        let context = retry_context.context();
        let deadline = retry_context.deadline();
        if let Some(error) = deadline.error_if_elapsed() {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let response_body = match self.read_response_body_with_retry(response, retry_context)? {
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
        if should_decode_response_body
            && response_headers.contains_key(http::header::CONTENT_ENCODING)
        {
            remove_content_encoding_headers(response_headers);
        }
        Ok(BodyReadOutcome::Body(response_body))
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
    ) -> Result<ureq::http::Response<ureq::Body>, Error> {
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
                    .map_err(|source| Error::RequestBuild { source })?;
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
                    .map_err(|source| Error::RequestBuild { source })?;
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
    ) -> Result<ureq::http::Response<ureq::Body>, Error> {
        let configured_request = agent
            .configure_request(request)
            .timeout_global(Some(timeout_value))
            .timeout_per_call(Some(timeout_value))
            .timeout_connect(Some(self.connect_timeout))
            .timeout_recv_response(Some(timeout_value))
            .timeout_recv_body(Some(timeout_value))
            .build();
        self.validate_proxy_authorization(using_proxy)?;

        agent
            .run(configured_request)
            .map_err(|source| match source {
                ureq::Error::Timeout(_) => Error::Timeout {
                    phase: TimeoutPhase::Transport,
                    timeout_ms: timeout_value.as_millis(),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                },
                other => transport_error(
                    classify_ureq_transport_error(&other),
                    method,
                    redact_uri_for_logs(uri_text),
                    other,
                ),
            })
    }

    fn validate_proxy_authorization(&self, using_proxy: bool) -> Result<(), Error> {
        if !using_proxy {
            return Ok(());
        }
        let Some(proxy_config) = &self.proxy_config else {
            return Ok(());
        };
        if proxy_config.authorization.is_none() {
            return Ok(());
        }
        Err(Error::InvalidProxyConfig {
            proxy_uri: redact_uri_for_logs(&proxy_config.uri.to_string()),
            message: "blocking proxy_authorization(...) is unsupported for ureq transport; set credentials in http_proxy URI (e.g. http://user:pass@proxy:port)".to_owned(),
        })
    }

    pub(super) fn send_request(
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
            ensure_accept_encoding_blocking(&method, &mut merged_headers);
        }

        let body = body.unwrap_or_else(|| RequestBody::Buffered(Bytes::new()));
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, false);

        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let effective_total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let _global_permit = match self.acquire_global_request_permit(
            effective_total_timeout,
            request_started_at,
            &method,
            &redacted_uri_text,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                self.metrics
                    .record_request_completed_error(&error, request_started_at.elapsed());
                self.metrics
                    .finish_otel_request_span_error(otel_span, &error);
                return Err(error);
            }
        };

        let result = self.send_request_with_retry(
            RetryRequestInput {
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body,
                execution_options,
            },
            request_started_at,
        );

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

    pub(super) fn send_request_stream(
        &self,
        method: Method,
        path: String,
        headers: HeaderMap,
        body: Option<RequestBody>,
        execution_options: RequestExecutionOptions,
    ) -> Result<BlockingResponseStream, Error> {
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
            ensure_accept_encoding_blocking(&method, &mut merged_headers);
        }

        let body = body.unwrap_or_else(|| RequestBody::Buffered(Bytes::new()));
        let mut otel_span = Some(self.metrics.start_otel_request_span(
            &method,
            &redacted_uri_text,
            true,
        ));

        self.metrics.record_request_started();
        let in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();
        let effective_total_timeout = execution_options.total_timeout.or(self.total_timeout);
        let global_permit = match self.acquire_global_request_permit(
            effective_total_timeout,
            request_started_at,
            &method,
            &redacted_uri_text,
        ) {
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

        match self.send_request_with_retry_mode(
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
        ) {
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

    fn send_request_with_retry(
        &self,
        input: RetryRequestInput<RequestBody>,
        request_started_at: Instant,
    ) -> Result<Response, Error> {
        let expected_method = input.method.clone();
        let expected_redacted_uri = input.redacted_uri_text.clone();
        match self.send_request_with_retry_mode(
            input,
            ResponseMode::Buffered,
            None,
            request_started_at,
        )? {
            RetryResponse::Buffered(response) => Ok(response),
            RetryResponse::Stream(_) => Err(response_mode_mismatch_error(
                &expected_method,
                &expected_redacted_uri,
                "buffered",
            )),
        }
    }

    fn send_request_with_retry_mode(
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
        let timeout_value = execution_options
            .request_timeout
            .unwrap_or(self.request_timeout);
        let total_timeout = execution_options.total_timeout.or(self.total_timeout);
        RequestTimeoutConfig {
            request_timeout: timeout_value,
            total_timeout,
        }
        .validate()?;
        let max_response_body_bytes = execution_options
            .max_response_body_bytes
            .unwrap_or(self.max_response_body_bytes);

        let (mut buffered_body, mut reader_body) = match body {
            RequestBody::Buffered(body) => (Some(body), None),
            RequestBody::Reader(reader) => (None, Some(reader)),
        };

        let body_replayable = buffered_body.is_some();
        let retry_policy = execution_options
            .retry_policy
            .unwrap_or_else(|| self.retry_policy.clone());
        retry_policy.validate()?;
        let redirect_policy = execution_options
            .redirect_policy
            .unwrap_or(self.redirect_policy);
        let status_policy = execution_options
            .status_policy
            .unwrap_or(self.default_status_policy);
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
            let context = execution.context();
            self.run_request_start_observers(&context);
            let rate_limit_host = execution.rate_limit_host();
            if let Err(error) = self.acquire_rate_limit_slot(
                rate_limit_host.as_deref(),
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
                self.run_error_interceptors(&context, &error);
                return Err(error);
            }
            let host_permit = match self.acquire_host_request_permit(
                rate_limit_host.as_deref(),
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
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
            let adaptive_attempt = match self.begin_adaptive_attempt(
                execution.total_timeout(),
                execution.request_started_at(),
                execution.current_method(),
                execution.current_redacted_uri(),
            ) {
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
            attempt_headers.remove(http::header::PROXY_AUTHORIZATION);
            let current_uri_text = execution.current_uri().to_string();
            let Some(transport_timeout) = execution.phase_timeout() else {
                let error = execution.deadline_error();
                attempts.cancel();
                self.run_error_interceptors(&context, &error);
                return Err(error);
            };

            let request_body = if let Some(body) = &buffered_body {
                RequestBody::Buffered(body.clone())
            } else {
                match reader_body.take() {
                    Some(reader) => RequestBody::Reader(reader),
                    None => RequestBody::Buffered(Bytes::new()),
                }
            };

            let mut response = match self.run_once(
                execution.current_method().clone(),
                execution.current_uri(),
                &current_uri_text,
                &attempt_headers,
                request_body,
                transport_timeout,
            ) {
                Ok(response) => response,
                Err(error) => {
                    let error = if matches!(
                        error,
                        Error::Timeout {
                            phase: TimeoutPhase::Transport,
                            ..
                        }
                    ) {
                        execution.transport_timeout_error(transport_timeout.as_millis())
                    } else {
                        error
                    };
                    match execution.transport_failure_plan(&error, self.backoff_source.as_ref()) {
                        TransportFailurePlan::Retry(retry_plan) => {
                            match attempts.record_failure_for_retry_schedule(self.prepare_retry(
                                execution.retry_attempt(),
                                &context,
                                &retry_plan.decision,
                                retry_plan.delay,
                            ))? {
                                RetrySchedule::Scheduled { delay: retry_delay } => {
                                    drop(host_permit);
                                    if !retry_delay.is_zero() {
                                        sleep(retry_delay);
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
                    reader_body = None;
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
                            sleep(retry_delay);
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
                    &mut response,
                    &mut response_headers,
                    status,
                    execution.body_read_retry_context(&context, read_timeout),
                ),
            )? {
                BodyReadOutcome::Body(body) => body,
                BodyReadOutcome::Retry(retry_delay) => {
                    attempts.mark_failure();
                    drop(response);
                    drop(host_permit);
                    if !retry_delay.is_zero() {
                        sleep(retry_delay);
                    }
                    continue;
                }
            };

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
