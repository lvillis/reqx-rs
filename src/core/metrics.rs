use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::Method;

use crate::error::{Error, TimeoutPhase};
use crate::otel::{OtelRequestSpan, OtelTelemetry};
#[cfg(feature = "_blocking")]
use crate::response::BlockingHttpResponseStream;
use crate::response::HttpResponse;
#[cfg(feature = "_async")]
use crate::response::HttpResponseStream;
use crate::util::lock_unpoisoned;

#[derive(Clone, Debug)]
pub struct HttpClientMetricsSnapshot {
    pub requests_started: u64,
    pub requests_succeeded: u64,
    pub requests_failed: u64,
    pub retries: u64,
    pub timeout_transport: u64,
    pub timeout_response_body: u64,
    pub deadline_exceeded: u64,
    pub transport_errors: u64,
    pub read_body_errors: u64,
    pub response_body_too_large: u64,
    pub http_status_errors: u64,
    pub in_flight: u64,
    pub latency_samples: u64,
    pub latency_total_ms: u64,
    pub latency_avg_ms: f64,
    pub status_counts: BTreeMap<u16, u64>,
    pub error_counts: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct HttpClientMetrics {
    inner: Option<Arc<HttpClientMetricsInner>>,
    otel: OtelTelemetry,
}

#[derive(Debug, Default)]
struct HttpClientMetricsInner {
    requests_started: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    retries: AtomicU64,
    timeout_transport: AtomicU64,
    timeout_response_body: AtomicU64,
    deadline_exceeded: AtomicU64,
    transport_errors: AtomicU64,
    read_body_errors: AtomicU64,
    response_body_too_large: AtomicU64,
    http_status_errors: AtomicU64,
    in_flight: AtomicU64,
    latency_total_ms: AtomicU64,
    latency_samples: AtomicU64,
    status_counts: Mutex<BTreeMap<u16, u64>>,
    error_counts: Mutex<BTreeMap<String, u64>>,
}

pub(crate) struct InFlightGuard {
    inner: Option<Arc<HttpClientMetricsInner>>,
}

impl HttpClientMetrics {
    pub(crate) fn with_options(metrics_enabled: bool, otel: OtelTelemetry) -> Self {
        Self {
            inner: metrics_enabled.then(|| Arc::new(HttpClientMetricsInner::default())),
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
        result: &Result<HttpResponse, Error>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                if let Some(inner) = &self.inner {
                    inner.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                }
                self.add_status_count(response.status().as_u16());
                self.otel
                    .record_request_succeeded(response.status().as_u16());
            }
            Err(error) => {
                self.record_request_completed_error(error, latency);
                return;
            }
        }

        self.record_latency(latency);
    }

    #[cfg(feature = "_async")]
    pub(crate) fn record_request_completed_stream(
        &self,
        result: &Result<HttpResponseStream, Error>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                if let Some(inner) = &self.inner {
                    inner.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                }
                self.add_status_count(response.status().as_u16());
                self.otel
                    .record_request_succeeded(response.status().as_u16());
            }
            Err(error) => {
                self.record_request_completed_error(error, latency);
                return;
            }
        }
        self.record_latency(latency);
    }

    #[cfg(feature = "_blocking")]
    pub(crate) fn record_request_completed_blocking_stream(
        &self,
        result: &Result<BlockingHttpResponseStream, Error>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                if let Some(inner) = &self.inner {
                    inner.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                }
                self.add_status_count(response.status().as_u16());
                self.otel
                    .record_request_succeeded(response.status().as_u16());
            }
            Err(error) => {
                self.record_request_completed_error(error, latency);
                return;
            }
        }
        self.record_latency(latency);
    }

    pub(crate) fn record_request_completed_error(&self, error: &Error, latency: Duration) {
        if let Some(inner) = &self.inner {
            inner.requests_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.record_latency(latency);
        self.otel.record_request_failed(error);

        self.add_error_count(error.code().as_str().to_owned());

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
                self.add_error_count(format!("timeout:{phase}"));
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
                self.add_error_count(format!("transport:{kind}"));
            }
            Error::ReadBody { .. } => {
                if let Some(inner) = &self.inner {
                    inner.read_body_errors.fetch_add(1, Ordering::Relaxed);
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
                self.add_error_count(format!("http_status:{status}"));
            }
            Error::InvalidUri { .. }
            | Error::SerializeJson { .. }
            | Error::SerializeQuery { .. }
            | Error::SerializeForm { .. }
            | Error::RequestBuild { .. }
            | Error::DeserializeJson { .. }
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

    pub(crate) fn snapshot(&self) -> HttpClientMetricsSnapshot {
        let Some(inner) = &self.inner else {
            return HttpClientMetricsSnapshot {
                requests_started: 0,
                requests_succeeded: 0,
                requests_failed: 0,
                retries: 0,
                timeout_transport: 0,
                timeout_response_body: 0,
                deadline_exceeded: 0,
                transport_errors: 0,
                read_body_errors: 0,
                response_body_too_large: 0,
                http_status_errors: 0,
                in_flight: 0,
                latency_samples: 0,
                latency_total_ms: 0,
                latency_avg_ms: 0.0,
                status_counts: BTreeMap::new(),
                error_counts: BTreeMap::new(),
            };
        };

        let requests_started = inner.requests_started.load(Ordering::Relaxed);
        let requests_succeeded = inner.requests_succeeded.load(Ordering::Relaxed);
        let requests_failed = inner.requests_failed.load(Ordering::Relaxed);
        let retries = inner.retries.load(Ordering::Relaxed);
        let timeout_transport = inner.timeout_transport.load(Ordering::Relaxed);
        let timeout_response_body = inner.timeout_response_body.load(Ordering::Relaxed);
        let deadline_exceeded = inner.deadline_exceeded.load(Ordering::Relaxed);
        let transport_errors = inner.transport_errors.load(Ordering::Relaxed);
        let read_body_errors = inner.read_body_errors.load(Ordering::Relaxed);
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
        let error_counts = lock_unpoisoned(&inner.error_counts).clone();

        HttpClientMetricsSnapshot {
            requests_started,
            requests_succeeded,
            requests_failed,
            retries,
            timeout_transport,
            timeout_response_body,
            deadline_exceeded,
            transport_errors,
            read_body_errors,
            response_body_too_large,
            http_status_errors,
            in_flight,
            latency_samples,
            latency_total_ms,
            latency_avg_ms,
            status_counts,
            error_counts,
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

    fn add_error_count(&self, error_key: String) {
        let Some(inner) = &self.inner else {
            return;
        };
        let mut error_counts = lock_unpoisoned(&inner.error_counts);
        *error_counts.entry(error_key).or_insert(0) += 1;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
