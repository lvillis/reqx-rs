use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::Method;

use crate::error::{Error, ErrorCode, TimeoutPhase, TransportErrorKind};
use crate::otel::{OtelRequestSpan, OtelTelemetry};
use crate::response::Response;
use crate::util::lock_unpoisoned;

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub requests: RequestMetrics,
    pub responses: ResponseMetrics,
    pub timeouts: TimeoutMetrics,
    pub errors: ErrorMetrics,
    pub latency: LatencyMetrics,
}

#[derive(Clone, Debug, Default)]
pub struct RequestMetrics {
    pub started: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub canceled: u64,
    pub retries: u64,
    pub in_flight: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ResponseMetrics {
    pub status_counts: BTreeMap<u16, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct TimeoutMetrics {
    pub transport: u64,
    pub response_body: u64,
    pub deadline_exceeded: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ErrorMetrics {
    pub transport: u64,
    pub read_body: u64,
    pub write_body: u64,
    pub response_body_too_large: u64,
    pub http_status: u64,
    pub by_code: BTreeMap<ErrorCode, u64>,
    pub by_timeout_phase: BTreeMap<TimeoutPhase, u64>,
    pub by_transport_kind: BTreeMap<TransportErrorKind, u64>,
    pub by_http_status: BTreeMap<u16, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct LatencyMetrics {
    pub samples: u64,
    pub total_ms: u64,
    pub average_ms: f64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ClientMetrics {
    inner: Option<Arc<ClientMetricsInner>>,
    otel: OtelTelemetry,
}

#[derive(Debug, Default)]
struct ClientMetricsInner {
    requests_started: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    requests_canceled: AtomicU64,
    retries: AtomicU64,
    timeout_transport: AtomicU64,
    timeout_response_body: AtomicU64,
    deadline_exceeded: AtomicU64,
    transport_errors: AtomicU64,
    read_body_errors: AtomicU64,
    write_body_errors: AtomicU64,
    response_body_too_large: AtomicU64,
    http_status_errors: AtomicU64,
    in_flight: AtomicU64,
    latency_total_ms: AtomicU64,
    latency_samples: AtomicU64,
    status_counts: Mutex<BTreeMap<u16, u64>>,
    error_code_counts: Mutex<BTreeMap<ErrorCode, u64>>,
    timeout_phase_counts: Mutex<BTreeMap<TimeoutPhase, u64>>,
    transport_error_kind_counts: Mutex<BTreeMap<TransportErrorKind, u64>>,
    http_status_error_counts: Mutex<BTreeMap<u16, u64>>,
}

#[derive(Debug)]
pub(crate) struct InFlightGuard {
    inner: Option<Arc<ClientMetricsInner>>,
}

#[derive(Debug)]
pub(crate) struct StreamCompletion {
    metrics: ClientMetrics,
    request_span: Option<OtelRequestSpan>,
    request_started_at: Instant,
    status: u16,
    in_flight_guard: Option<InFlightGuard>,
    state: StreamCompletionState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamCompletionState {
    Pending,
    Success,
    Error,
    Canceled,
}

impl ClientMetrics {
    pub(crate) fn with_options(metrics_enabled: bool, otel: OtelTelemetry) -> Self {
        Self {
            inner: metrics_enabled.then(|| Arc::new(ClientMetricsInner::default())),
            otel,
        }
    }

    pub(crate) fn start_otel_request_span(
        &self,
        method: &Method,
        uri: &str,
        stream: bool,
    ) -> OtelRequestSpan {
        self.otel.start_request_span(method, uri, stream)
    }

    pub(crate) fn finish_otel_request_span_success(
        &self,
        request_span: OtelRequestSpan,
        status: u16,
    ) {
        self.otel.finish_request_span_success(request_span, status);
    }

    pub(crate) fn finish_otel_request_span_error(
        &self,
        request_span: OtelRequestSpan,
        error: &Error,
    ) {
        self.otel.finish_request_span_error(request_span, error);
    }

    pub(crate) fn finish_otel_request_span_canceled(&self, request_span: OtelRequestSpan) {
        self.otel.finish_request_span_canceled(request_span);
    }

    pub(crate) fn record_request_started(&self) {
        if let Some(inner) = &self.inner {
            inner.requests_started.fetch_add(1, Ordering::Relaxed);
        }
        self.otel.record_request_started();
    }

    pub(crate) fn enter_in_flight(&self) -> InFlightGuard {
        match &self.inner {
            Some(inner) => {
                inner.in_flight.fetch_add(1, Ordering::Relaxed);
                InFlightGuard {
                    inner: Some(Arc::clone(inner)),
                }
            }
            None => InFlightGuard { inner: None },
        }
    }

    pub(crate) fn record_retry(&self) {
        if let Some(inner) = &self.inner {
            inner.retries.fetch_add(1, Ordering::Relaxed);
        }
        self.otel.record_retry();
    }

    pub(crate) fn record_request_completed(
        &self,
        result: &Result<Response, Error>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                self.record_request_completed_success(response.status().as_u16(), latency)
            }
            Err(error) => {
                self.record_request_completed_error(error, latency);
            }
        }
    }

    pub(crate) fn stream_completion(
        &self,
        request_span: Option<OtelRequestSpan>,
        request_started_at: Instant,
        status: u16,
        in_flight_guard: InFlightGuard,
    ) -> StreamCompletion {
        StreamCompletion {
            metrics: self.clone(),
            request_span,
            request_started_at,
            status,
            in_flight_guard: Some(in_flight_guard),
            state: StreamCompletionState::Pending,
        }
    }

    pub(crate) fn record_request_completed_error(&self, error: &Error, latency: Duration) {
        if let Some(inner) = &self.inner {
            inner.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.record_latency(latency);
        self.otel.record_request_failed(error);

        self.add_error_code_count(error.code());

        match error {
            Error::Timeout { phase, .. } => {
                if let Some(inner) = &self.inner {
                    match phase {
                        TimeoutPhase::Transport => {
                            inner.timeout_transport.fetch_add(1, Ordering::Relaxed);
                        }
                        TimeoutPhase::ResponseBody => {
                            inner.timeout_response_body.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                self.add_timeout_phase_count(*phase);
            }
            Error::DeadlineExceeded { .. } => {
                if let Some(inner) = &self.inner {
                    inner.deadline_exceeded.fetch_add(1, Ordering::Relaxed);
                }
            }
            Error::Transport { kind, .. } => {
                if let Some(inner) = &self.inner {
                    inner.transport_errors.fetch_add(1, Ordering::Relaxed);
                }
                self.add_transport_error_kind_count(*kind);
            }
            Error::ReadBody { .. } => {
                if let Some(inner) = &self.inner {
                    inner.read_body_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            Error::WriteBody { .. } => {
                if let Some(inner) = &self.inner {
                    inner.write_body_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            Error::ResponseBodyTooLarge { .. } => {
                if let Some(inner) = &self.inner {
                    inner
                        .response_body_too_large
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Error::HttpStatus { status, .. } => {
                if let Some(inner) = &self.inner {
                    inner.http_status_errors.fetch_add(1, Ordering::Relaxed);
                }
                self.add_status_count(*status);
                self.add_http_status_error_count(*status);
            }
            Error::InvalidUri { .. }
            | Error::InvalidNoProxyRule { .. }
            | Error::InvalidProxyConfig { .. }
            | Error::ProxyAuthorizationRequiresHttpProxy
            | Error::InvalidAdaptiveConcurrencyPolicy { .. }
            | Error::SerializeJson { .. }
            | Error::SerializeQuery { .. }
            | Error::SerializeForm { .. }
            | Error::RequestBuild { .. }
            | Error::DeserializeJson { .. }
            | Error::DecodeText { .. }
            | Error::InvalidHeaderName { .. }
            | Error::InvalidHeaderValue { .. }
            | Error::DecodeContentEncoding { .. }
            | Error::ConcurrencyLimitClosed
            | Error::TlsBackendUnavailable { .. }
            | Error::TlsBackendInit { .. }
            | Error::TlsConfig { .. }
            | Error::RetryBudgetExhausted { .. }
            | Error::CircuitOpen { .. }
            | Error::MissingRedirectLocation { .. }
            | Error::InvalidRedirectLocation { .. }
            | Error::RedirectLimitExceeded { .. }
            | Error::RedirectBodyNotReplayable { .. } => {}
        }
    }

    pub(crate) fn record_request_completed_canceled(&self, latency: Duration) {
        if let Some(inner) = &self.inner {
            inner.requests_canceled.fetch_add(1, Ordering::Relaxed);
        }
        self.record_latency(latency);
        self.otel.record_request_canceled();
    }

    fn record_request_completed_success(&self, status: u16, latency: Duration) {
        if let Some(inner) = &self.inner {
            inner.requests_succeeded.fetch_add(1, Ordering::Relaxed);
        }
        self.add_status_count(status);
        self.otel.record_request_succeeded(status);
        self.record_latency(latency);
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        let Some(inner) = &self.inner else {
            return MetricsSnapshot::default();
        };

        let requests_started = inner.requests_started.load(Ordering::Relaxed);
        let requests_succeeded = inner.requests_succeeded.load(Ordering::Relaxed);
        let requests_failed = inner.requests_failed.load(Ordering::Relaxed);
        let requests_canceled = inner.requests_canceled.load(Ordering::Relaxed);
        let retries = inner.retries.load(Ordering::Relaxed);
        let timeout_transport = inner.timeout_transport.load(Ordering::Relaxed);
        let timeout_response_body = inner.timeout_response_body.load(Ordering::Relaxed);
        let deadline_exceeded = inner.deadline_exceeded.load(Ordering::Relaxed);
        let transport_errors = inner.transport_errors.load(Ordering::Relaxed);
        let read_body_errors = inner.read_body_errors.load(Ordering::Relaxed);
        let write_body_errors = inner.write_body_errors.load(Ordering::Relaxed);
        let response_body_too_large = inner.response_body_too_large.load(Ordering::Relaxed);
        let http_status_errors = inner.http_status_errors.load(Ordering::Relaxed);
        let in_flight = inner.in_flight.load(Ordering::Relaxed);
        let latency_samples = inner.latency_samples.load(Ordering::Relaxed);
        let latency_total_ms = inner.latency_total_ms.load(Ordering::Relaxed);
        let latency_avg_ms = if latency_samples == 0 {
            0.0
        } else {
            latency_total_ms as f64 / latency_samples as f64
        };
        let status_counts = lock_unpoisoned(&inner.status_counts).clone();
        let error_code_counts = lock_unpoisoned(&inner.error_code_counts).clone();
        let timeout_phase_counts = lock_unpoisoned(&inner.timeout_phase_counts).clone();
        let transport_error_kind_counts =
            lock_unpoisoned(&inner.transport_error_kind_counts).clone();
        let http_status_error_counts = lock_unpoisoned(&inner.http_status_error_counts).clone();

        MetricsSnapshot {
            requests: RequestMetrics {
                started: requests_started,
                succeeded: requests_succeeded,
                failed: requests_failed,
                canceled: requests_canceled,
                retries,
                in_flight,
            },
            responses: ResponseMetrics { status_counts },
            timeouts: TimeoutMetrics {
                transport: timeout_transport,
                response_body: timeout_response_body,
                deadline_exceeded,
            },
            errors: ErrorMetrics {
                transport: transport_errors,
                read_body: read_body_errors,
                write_body: write_body_errors,
                response_body_too_large,
                http_status: http_status_errors,
                by_code: error_code_counts,
                by_timeout_phase: timeout_phase_counts,
                by_transport_kind: transport_error_kind_counts,
                by_http_status: http_status_error_counts,
            },
            latency: LatencyMetrics {
                samples: latency_samples,
                total_ms: latency_total_ms,
                average_ms: latency_avg_ms,
            },
        }
    }

    fn record_latency(&self, latency: Duration) {
        self.otel.record_request_latency(latency);

        let Some(inner) = &self.inner else {
            return;
        };
        inner.latency_samples.fetch_add(1, Ordering::Relaxed);
        inner.latency_total_ms.fetch_add(
            latency.as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn add_status_count(&self, status: u16) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut status_counts = lock_unpoisoned(&inner.status_counts);
        *status_counts.entry(status).or_insert(0) += 1;
    }

    fn add_error_code_count(&self, error_code: ErrorCode) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut error_code_counts = lock_unpoisoned(&inner.error_code_counts);
        *error_code_counts.entry(error_code).or_insert(0) += 1;
    }

    fn add_timeout_phase_count(&self, phase: TimeoutPhase) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut timeout_phase_counts = lock_unpoisoned(&inner.timeout_phase_counts);
        *timeout_phase_counts.entry(phase).or_insert(0) += 1;
    }

    fn add_transport_error_kind_count(&self, kind: TransportErrorKind) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut transport_error_kind_counts = lock_unpoisoned(&inner.transport_error_kind_counts);
        *transport_error_kind_counts.entry(kind).or_insert(0) += 1;
    }

    fn add_http_status_error_count(&self, status: u16) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut http_status_error_counts = lock_unpoisoned(&inner.http_status_error_counts);
        *http_status_error_counts.entry(status).or_insert(0) += 1;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl StreamCompletion {
    pub(crate) fn complete_success(&mut self) {
        if self.state != StreamCompletionState::Pending {
            return;
        }
        self.state = StreamCompletionState::Success;
        let latency = self.request_started_at.elapsed();
        self.metrics
            .record_request_completed_success(self.status, latency);
        if let Some(span) = self.request_span.take() {
            self.metrics
                .finish_otel_request_span_success(span, self.status);
        }
        let _ = self.in_flight_guard.take();
    }

    pub(crate) fn complete_error(&mut self, error: &Error) {
        if self.state != StreamCompletionState::Pending {
            return;
        }
        self.state = StreamCompletionState::Error;
        let latency = self.request_started_at.elapsed();
        self.metrics.record_request_completed_error(error, latency);
        if let Some(span) = self.request_span.take() {
            self.metrics.finish_otel_request_span_error(span, error);
        }
        let _ = self.in_flight_guard.take();
    }

    pub(crate) fn complete_canceled(&mut self) {
        if self.state != StreamCompletionState::Pending {
            return;
        }
        self.state = StreamCompletionState::Canceled;
        let latency = self.request_started_at.elapsed();
        self.metrics.record_request_completed_canceled(latency);
        if let Some(span) = self.request_span.take() {
            self.metrics.finish_otel_request_span_canceled(span);
        }
        let _ = self.in_flight_guard.take();
    }
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        self.complete_canceled();
    }
}
