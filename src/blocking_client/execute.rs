use std::thread::sleep;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

use crate::content_encoding::should_decode_content_encoded_body;
use crate::error::{Error, TimeoutPhase};
use crate::execution::{
    effective_status_policy, http_status_error, select_base_url, status_retry_decision,
    status_retry_delay,
};
use crate::metrics::MetricsSnapshot;
use crate::policy::{RequestContext, StatusPolicy};
use crate::rate_limit::server_throttle_scope_from_headers;
use crate::response::{BlockingResponseStream, Response};
use crate::retry::{RetryDecision, RetryPolicy};
use crate::tls::TlsBackend;
use crate::util::{
    bounded_retry_delay, deadline_exceeded_error, ensure_accept_encoding_blocking,
    is_redirect_status, merge_headers, phase_timeout, rate_limit_bucket_key, redact_uri_for_logs,
    redirect_location, redirect_method, resolve_redirect_uri, resolve_uri, same_origin,
    sanitize_headers_for_redirect, truncate_body,
};

use super::transport::{
    ReadBodyError, classify_ureq_transport_error, is_proxy_bypassed, read_all_body_limited,
    remove_content_encoding_headers, wrapped_ureq_error,
};
use super::{
    AdaptiveConcurrencyPermit, Client, ClientBuilder, RequestBody, RequestBuilder,
    RequestExecutionOptions,
};

struct BodyReadRetryContext<'a> {
    context: &'a RequestContext,
    max_response_body_bytes: usize,
    transport_timeout: Duration,
    retry_policy: &'a RetryPolicy,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    current_method: &'a Method,
    current_redacted_uri: &'a str,
    attempt: &'a mut usize,
    max_attempts: usize,
}

struct RetryScheduleContext<'a> {
    context: &'a RequestContext,
    retry_policy: &'a RetryPolicy,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    current_method: &'a Method,
    current_redacted_uri: &'a str,
    attempt: &'a mut usize,
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
    Stream(BlockingResponseStream),
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

    fn schedule_retry(
        &self,
        retry_context: RetryScheduleContext<'_>,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
    ) -> Result<bool, Error> {
        let RetryScheduleContext {
            context,
            retry_policy,
            total_timeout,
            request_started_at,
            current_method,
            current_redacted_uri,
            attempt,
            max_attempts,
        } = retry_context;

        if *attempt >= max_attempts || !retry_policy.should_retry_decision(retry_decision) {
            return Ok(false);
        }

        if let Err(error) = self.try_consume_retry_budget(current_method, current_redacted_uri) {
            self.run_error_interceptors(context, &error);
            return Err(error);
        }
        let Some(retry_delay) =
            bounded_retry_delay(requested_delay, total_timeout, request_started_at)
        else {
            let error =
                deadline_exceeded_error(total_timeout, current_method, current_redacted_uri);
            self.run_error_interceptors(context, &error);
            return Err(error);
        };

        self.metrics.record_retry();
        self.run_retry_observers(context, retry_decision, retry_delay);
        if !retry_delay.is_zero() {
            sleep(retry_delay);
        }
        *attempt += 1;
        Ok(true)
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

    fn read_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        retry_context: BodyReadRetryContext<'_>,
    ) -> Result<Option<Bytes>, Error> {
        let BodyReadRetryContext {
            context,
            max_response_body_bytes,
            transport_timeout,
            retry_policy,
            total_timeout,
            request_started_at,
            current_method,
            current_redacted_uri,
            attempt,
            max_attempts,
        } = retry_context;

        match read_all_body_limited(response, max_response_body_bytes) {
            Ok(body) => Ok(Some(body)),
            Err(ReadBodyError::TooLarge { actual_bytes }) => {
                let error = Error::ResponseBodyTooLarge {
                    limit_bytes: max_response_body_bytes,
                    actual_bytes,
                    method: current_method.clone(),
                    uri: current_redacted_uri.to_owned(),
                };
                self.run_error_interceptors(context, &error);
                Err(error)
            }
            Err(ReadBodyError::Read(source)) => {
                if let Some(ureq_error) = wrapped_ureq_error(&source)
                    && let ureq::Error::Timeout(timeout) = ureq_error
                {
                    let _ = timeout;
                    let timeout_phase = TimeoutPhase::ResponseBody;
                    let error = Error::Timeout {
                        phase: timeout_phase,
                        timeout_ms: transport_timeout.as_millis(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.to_owned(),
                    };
                    let retry_decision = RetryDecision {
                        attempt: *attempt,
                        max_attempts,
                        method: current_method.clone(),
                        uri: current_redacted_uri.to_owned(),
                        status: None,
                        transport_error_kind: None,
                        timeout_phase: Some(timeout_phase),
                        response_body_read_error: false,
                    };
                    let retry_delay = self
                        .backoff_source
                        .backoff_for_retry(retry_policy, *attempt);
                    if self.schedule_retry(
                        RetryScheduleContext {
                            context,
                            retry_policy,
                            total_timeout,
                            request_started_at,
                            current_method,
                            current_redacted_uri,
                            attempt,
                            max_attempts,
                        },
                        &retry_decision,
                        retry_delay,
                    )? {
                        return Ok(None);
                    }
                    self.run_error_interceptors(context, &error);
                    return Err(error);
                }

                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                let retry_decision = RetryDecision {
                    attempt: *attempt,
                    max_attempts,
                    method: current_method.clone(),
                    uri: current_redacted_uri.to_owned(),
                    status: None,
                    transport_error_kind: None,
                    timeout_phase: None,
                    response_body_read_error: true,
                };
                let retry_delay = self
                    .backoff_source
                    .backoff_for_retry(retry_policy, *attempt);
                if self.schedule_retry(
                    RetryScheduleContext {
                        context,
                        retry_policy,
                        total_timeout,
                        request_started_at,
                        current_method,
                        current_redacted_uri,
                        attempt,
                        max_attempts,
                    },
                    &retry_decision,
                    retry_delay,
                )? {
                    return Ok(None);
                }
                self.run_error_interceptors(context, &error);
                Err(error)
            }
        }
    }

    fn read_decoded_response_body_with_retry(
        &self,
        response: &mut ureq::http::Response<ureq::Body>,
        response_headers: &mut HeaderMap,
        status: http::StatusCode,
        retry_context: BodyReadRetryContext<'_>,
    ) -> Result<Option<Bytes>, Error> {
        let max_response_body_bytes = retry_context.max_response_body_bytes;
        let context = retry_context.context;
        let response_body = match self.read_response_body_with_retry(response, retry_context)? {
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
        if should_decode_response_body
            && response_headers.contains_key(http::header::CONTENT_ENCODING)
        {
            remove_content_encoding_headers(response_headers);
        }
        Ok(Some(response_body))
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
                ureq::Error::Timeout(_) => Error::Timeout {
                    phase: TimeoutPhase::Transport,
                    timeout_ms: timeout_value.as_millis(),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                },
                other => Error::Transport {
                    kind: classify_ureq_transport_error(&other),
                    method,
                    uri: redact_uri_for_logs(uri_text),
                    source: Box::new(other),
                },
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
        let otel_span = self
            .metrics
            .start_otel_request_span(&method, &redacted_uri_text, true);

        self.metrics.record_request_started();
        let _in_flight = self.metrics.enter_in_flight();
        let request_started_at = Instant::now();

        let result = self.send_request_stream_with_retry(
            method,
            uri,
            redacted_uri_text,
            merged_headers,
            body,
            execution_options,
        );

        self.metrics
            .record_request_completed_blocking_stream(&result, request_started_at.elapsed());
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

    fn send_request_stream_with_retry(
        &self,
        method: Method,
        uri: Uri,
        redacted_uri_text: String,
        merged_headers: HeaderMap,
        body: RequestBody,
        execution_options: RequestExecutionOptions,
    ) -> Result<BlockingResponseStream, Error> {
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
        )? {
            RetryResponse::Stream(response) => Ok(response),
            RetryResponse::Buffered(_) => unreachable!("stream mode returned buffered response"),
        }
    }

    fn send_request_with_retry(
        &self,
        method: Method,
        uri: Uri,
        redacted_uri_text: String,
        merged_headers: HeaderMap,
        body: RequestBody,
        execution_options: RequestExecutionOptions,
    ) -> Result<Response, Error> {
        match self.send_request_with_retry_mode(
            RetryRequestInput {
                method,
                uri,
                redacted_uri_text,
                merged_headers,
                body,
                execution_options,
            },
            ResponseMode::Buffered,
        )? {
            RetryResponse::Buffered(response) => Ok(response),
            RetryResponse::Stream(_) => unreachable!("buffered mode returned stream response"),
        }
    }

    fn send_request_with_retry_mode(
        &self,
        input: RetryRequestInput,
        response_mode: ResponseMode,
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

        let (mut buffered_body, mut reader_body) = match body {
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
            self.run_request_start_observers(&context);
            let rate_limit_host = rate_limit_bucket_key(&current_uri);
            if let Err(error) = self.acquire_rate_limit_slot(
                rate_limit_host.as_deref(),
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
                        Error::Transport { kind, .. } => RetryDecision {
                            attempt,
                            max_attempts,
                            method: current_method.clone(),
                            uri: current_redacted_uri.clone(),
                            status: None,
                            transport_error_kind: Some(*kind),
                            timeout_phase: None,
                            response_body_read_error: false,
                        },
                        Error::Timeout { phase, .. } => RetryDecision {
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

                    let retry_delay = self
                        .backoff_source
                        .backoff_for_retry(&retry_policy, attempt);
                    if self.schedule_retry(
                        RetryScheduleContext {
                            context: &context,
                            retry_policy: &retry_policy,
                            total_timeout,
                            request_started_at,
                            current_method: &current_method,
                            current_redacted_uri: &current_redacted_uri,
                            attempt: &mut attempt,
                            max_attempts,
                        },
                        &retry_decision,
                        retry_delay,
                    )? {
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
                    let error = Error::RedirectLimitExceeded {
                        max_redirects: redirect_policy.max_redirects(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                let next_method = redirect_method(&current_method, status);
                let method_changed_to_get =
                    next_method == Method::GET && current_method != Method::GET;
                if !body_replayable
                    && !method_changed_to_get
                    && !matches!(
                        current_method,
                        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
                    )
                {
                    let error = Error::RedirectBodyNotReplayable {
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                }
                let Some(location) = redirect_location(&response_headers) else {
                    let error = Error::MissingRedirectLocation {
                        status: status.as_u16(),
                        method: current_method.clone(),
                        uri: current_redacted_uri.clone(),
                    };
                    self.run_error_interceptors(&context, &error);
                    return Err(error);
                };
                let Some(next_uri) = resolve_redirect_uri(&current_uri, &location) else {
                    let error = Error::InvalidRedirectLocation {
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
                let same_origin_redirect = same_origin(&current_uri, &next_uri);
                sanitize_headers_for_redirect(
                    &mut current_headers,
                    method_changed_to_get,
                    same_origin_redirect,
                );
                if method_changed_to_get {
                    buffered_body = None;
                    reader_body = None;
                }
                current_method = next_method;
                current_uri = next_uri;
                current_redacted_uri = redact_uri_for_logs(&current_uri.to_string());
                redirect_count += 1;
                if max_attempts == 1
                    && (body_replayable || method_changed_to_get)
                    && self
                        .retry_eligibility
                        .supports_retry(&current_method, &current_headers)
                {
                    max_attempts = retry_policy.configured_max_attempts();
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
                    return Ok(RetryResponse::Stream(BlockingResponseStream::new(
                        status,
                        response_headers,
                        response.into_body(),
                        current_method.clone(),
                        current_redacted_uri.clone(),
                        transport_timeout.as_millis(),
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
                let retry_decision = status_retry_decision(
                    attempt,
                    max_attempts,
                    &current_method,
                    &current_redacted_uri,
                    status,
                );
                let retry_delay = status_retry_delay(
                    self.clock.as_ref(),
                    &response_headers,
                    self.backoff_source
                        .backoff_for_retry(&retry_policy, attempt),
                );
                evaluated_status_retry = true;
                if self.schedule_retry(
                    RetryScheduleContext {
                        context: &context,
                        retry_policy: &retry_policy,
                        total_timeout,
                        request_started_at,
                        current_method: &current_method,
                        current_redacted_uri: &current_redacted_uri,
                        attempt: &mut attempt,
                        max_attempts,
                    },
                    &retry_decision,
                    retry_delay,
                )? {
                    continue;
                }
                if matches!(status_policy, StatusPolicy::Response) {
                    self.maybe_record_terminal_response_success(status, &retry_policy);
                    if let Some(attempt_guard) = circuit_attempt.take() {
                        attempt_guard.mark_success();
                    }
                    if let Some(adaptive_guard) = adaptive_attempt.take() {
                        adaptive_guard.mark_success();
                    }
                    return Ok(RetryResponse::Stream(BlockingResponseStream::new(
                        status,
                        response_headers,
                        response.into_body(),
                        current_method.clone(),
                        current_redacted_uri.clone(),
                        transport_timeout.as_millis(),
                    )));
                }
            }

            let response_body = match self.read_decoded_response_body_with_retry(
                &mut response,
                &mut response_headers,
                status,
                BodyReadRetryContext {
                    context: &context,
                    max_response_body_bytes,
                    transport_timeout,
                    retry_policy: &retry_policy,
                    total_timeout,
                    request_started_at,
                    current_method: &current_method,
                    current_redacted_uri: &current_redacted_uri,
                    attempt: &mut attempt,
                    max_attempts,
                },
            )? {
                Some(body) => body,
                None => continue,
            };

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
                    let retry_decision = status_retry_decision(
                        attempt,
                        max_attempts,
                        &current_method,
                        &current_redacted_uri,
                        status,
                    );

                    let retry_delay = status_retry_delay(
                        self.clock.as_ref(),
                        &response_headers,
                        self.backoff_source
                            .backoff_for_retry(&retry_policy, attempt),
                    );
                    if self.schedule_retry(
                        RetryScheduleContext {
                            context: &context,
                            retry_policy: &retry_policy,
                            total_timeout,
                            request_started_at,
                            current_method: &current_method,
                            current_redacted_uri: &current_redacted_uri,
                            attempt: &mut attempt,
                            max_attempts,
                        },
                        &retry_decision,
                        retry_delay,
                    )? {
                        continue;
                    }
                    if matches!(status_policy, StatusPolicy::Response)
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
