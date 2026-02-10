use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use http::header::CONTENT_ENCODING;
use http::{HeaderMap, Method, Uri};

use crate::error::{HttpClientError, TimeoutPhase};
use crate::metrics::HttpClientMetricsSnapshot;
use crate::policy::RequestContext;
use crate::rate_limit::server_throttle_scope_from_headers;
use crate::response::{BlockingHttpResponseStream, HttpResponse};
use crate::retry::RetryDecision;
use crate::tls::TlsBackend;
use crate::util::{
    bounded_retry_delay, deadline_exceeded_error, ensure_accept_encoding, is_redirect_status,
    merge_headers, parse_retry_after, phase_timeout, rate_limit_bucket_key, redact_uri_for_logs,
    redirect_location, redirect_method, resolve_redirect_uri, resolve_uri, same_origin,
    sanitize_headers_for_redirect, truncate_body,
};

use super::transport::{
    ReadBodyError, classify_ureq_transport_error, decode_content_encoding_error, is_proxy_bypassed,
    read_all_body_limited, remove_content_encoding_headers, wrapped_ureq_error,
};
use super::{
    AdaptiveConcurrencyPermit, HttpClient, HttpClientBuilder, RequestBody, RequestBuilder,
    RequestExecutionOptions,
};

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
        rate_limiter.observe_server_throttle(
            host,
            throttle_delay,
            self.server_throttle_scope,
            server_throttle_scope_from_headers(headers),
        );
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

    pub(super) fn send_request(
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
    ) -> Result<BlockingHttpResponseStream, HttpClientError> {
        let (uri_text, uri) = resolve_uri(&self.base_url, &path)?;
        let redacted_uri_text = redact_uri_for_logs(&uri_text);
        let mut merged_headers = merge_headers(&self.default_headers, &headers);
        ensure_accept_encoding(&mut merged_headers);

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
    ) -> Result<BlockingHttpResponseStream, HttpClientError> {
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

            if !status.is_success() {
                let response_body =
                    match read_all_body_limited(&mut response, max_response_body_bytes) {
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
                                    let _ = timeout;
                                    let timeout_phase = TimeoutPhase::ResponseBody;
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
                                if let ureq::Error::Decompress(encoding, decode_error) = ureq_error
                                {
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
                    };

                if response_headers.contains_key(CONTENT_ENCODING) {
                    remove_content_encoding_headers(&mut response_headers);
                }
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
                        sleep(retry_delay);
                    }
                    attempt += 1;
                    continue;
                }

                self.run_error_interceptors(&context, &error);
                return Err(error);
            }

            if response_headers.contains_key(CONTENT_ENCODING) {
                remove_content_encoding_headers(&mut response_headers);
            }
            self.run_response_interceptors(&context, status, &response_headers);
            if let Some(attempt_guard) = circuit_attempt.take() {
                attempt_guard.mark_success();
            }
            if let Some(adaptive_guard) = adaptive_attempt.take() {
                adaptive_guard.mark_success();
            }
            self.record_successful_request_for_resilience();
            return Ok(BlockingHttpResponseStream::new(
                status,
                response_headers,
                response.into_body(),
                current_method.clone(),
                current_redacted_uri.clone(),
                transport_timeout.as_millis(),
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
                            let _ = timeout;
                            let timeout_phase = TimeoutPhase::ResponseBody;
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
