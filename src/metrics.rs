use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::error::{HttpClientError, TimeoutPhase};
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
    inner: Arc<HttpClientMetricsInner>,
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
    metrics: HttpClientMetrics,
}

impl HttpClientMetrics {
    pub(crate) fn record_request_started(&self) {
        self.inner.requests_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn enter_in_flight(&self) -> InFlightGuard {
        self.inner.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlightGuard {
            metrics: self.clone(),
        }
    }

    pub(crate) fn record_retry(&self) {
        self.inner.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_request_completed(
        &self,
        result: &Result<HttpResponse, HttpClientError>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                self.inner
                    .requests_succeeded
                    .fetch_add(1, Ordering::Relaxed);
                self.add_status_count(response.status().as_u16());
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
        result: &Result<HttpResponseStream, HttpClientError>,
        latency: Duration,
    ) {
        match result {
            Ok(response) => {
                self.inner
                    .requests_succeeded
                    .fetch_add(1, Ordering::Relaxed);
                self.add_status_count(response.status().as_u16());
            }
            Err(error) => {
                self.record_request_completed_error(error, latency);
                return;
            }
        }
        self.record_latency(latency);
    }

    pub(crate) fn record_request_completed_error(
        &self,
        error: &HttpClientError,
        latency: Duration,
    ) {
        self.inner.requests_failed.fetch_add(1, Ordering::Relaxed);
        self.record_latency(latency);
        match error {
            HttpClientError::Timeout { phase, .. } => {
                match phase {
                    TimeoutPhase::Transport => {
                        self.inner.timeout_transport.fetch_add(1, Ordering::Relaxed);
                    }
                    TimeoutPhase::ResponseBody => {
                        self.inner
                            .timeout_response_body
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.add_error_count(format!("timeout:{phase}"));
            }
            HttpClientError::DeadlineExceeded { .. } => {
                self.inner.deadline_exceeded.fetch_add(1, Ordering::Relaxed);
                self.add_error_count("deadline_exceeded".to_owned());
            }
            HttpClientError::Transport { kind, .. } => {
                self.inner.transport_errors.fetch_add(1, Ordering::Relaxed);
                self.add_error_count(format!("transport:{kind}"));
            }
            HttpClientError::ReadBody { .. } => {
                self.inner.read_body_errors.fetch_add(1, Ordering::Relaxed);
                self.add_error_count("read_body".to_owned());
            }
            HttpClientError::ResponseBodyTooLarge { .. } => {
                self.inner
                    .response_body_too_large
                    .fetch_add(1, Ordering::Relaxed);
                self.add_error_count("response_body_too_large".to_owned());
            }
            HttpClientError::HttpStatus { status, .. } => {
                self.inner
                    .http_status_errors
                    .fetch_add(1, Ordering::Relaxed);
                self.add_status_count(*status);
                self.add_error_count(format!("http_status:{status}"));
            }
            HttpClientError::InvalidUri { .. } => {
                self.add_error_count("invalid_uri".to_owned());
            }
            HttpClientError::Serialize { .. } => {
                self.add_error_count("serialize".to_owned());
            }
            HttpClientError::SerializeQuery { .. } => {
                self.add_error_count("serialize_query".to_owned());
            }
            HttpClientError::SerializeForm { .. } => {
                self.add_error_count("serialize_form".to_owned());
            }
            HttpClientError::RequestBuild { .. } => {
                self.add_error_count("request_build".to_owned());
            }
            HttpClientError::Deserialize { .. } => {
                self.add_error_count("deserialize".to_owned());
            }
            HttpClientError::InvalidHeaderName { .. } => {
                self.add_error_count("invalid_header_name".to_owned());
            }
            HttpClientError::InvalidHeaderValue { .. } => {
                self.add_error_count("invalid_header_value".to_owned());
            }
            HttpClientError::DecodeContentEncoding { .. } => {
                self.add_error_count("decode_content_encoding".to_owned());
            }
            HttpClientError::ConcurrencyLimitClosed => {
                self.add_error_count("concurrency_limit_closed".to_owned());
            }
            HttpClientError::TlsBackendUnavailable { .. } => {
                self.add_error_count("tls_backend_unavailable".to_owned());
            }
            HttpClientError::TlsBackendInit { .. } => {
                self.add_error_count("tls_backend_init".to_owned());
            }
            HttpClientError::TlsConfig { .. } => {
                self.add_error_count("tls_config".to_owned());
            }
            HttpClientError::MissingRedirectLocation { .. } => {
                self.add_error_count("missing_redirect_location".to_owned());
            }
            HttpClientError::InvalidRedirectLocation { .. } => {
                self.add_error_count("invalid_redirect_location".to_owned());
            }
            HttpClientError::RedirectLimitExceeded { .. } => {
                self.add_error_count("redirect_limit_exceeded".to_owned());
            }
            HttpClientError::RedirectBodyNotReplayable { .. } => {
                self.add_error_count("redirect_body_not_replayable".to_owned());
            }
        }
    }

    pub(crate) fn snapshot(&self) -> HttpClientMetricsSnapshot {
        let requests_started = self.inner.requests_started.load(Ordering::Relaxed);
        let requests_succeeded = self.inner.requests_succeeded.load(Ordering::Relaxed);
        let requests_failed = self.inner.requests_failed.load(Ordering::Relaxed);
        let retries = self.inner.retries.load(Ordering::Relaxed);
        let timeout_transport = self.inner.timeout_transport.load(Ordering::Relaxed);
        let timeout_response_body = self.inner.timeout_response_body.load(Ordering::Relaxed);
        let deadline_exceeded = self.inner.deadline_exceeded.load(Ordering::Relaxed);
        let transport_errors = self.inner.transport_errors.load(Ordering::Relaxed);
        let read_body_errors = self.inner.read_body_errors.load(Ordering::Relaxed);
        let response_body_too_large = self.inner.response_body_too_large.load(Ordering::Relaxed);
        let http_status_errors = self.inner.http_status_errors.load(Ordering::Relaxed);
        let in_flight = self.inner.in_flight.load(Ordering::Relaxed);
        let latency_samples = self.inner.latency_samples.load(Ordering::Relaxed);
        let latency_total_ms = self.inner.latency_total_ms.load(Ordering::Relaxed);
        let latency_avg_ms = if latency_samples == 0 {
            0.0
        } else {
            latency_total_ms as f64 / latency_samples as f64
        };
        let status_counts = lock_unpoisoned(&self.inner.status_counts).clone();
        let error_counts = lock_unpoisoned(&self.inner.error_counts).clone();

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
        self.inner.latency_samples.fetch_add(1, Ordering::Relaxed);
        self.inner.latency_total_ms.fetch_add(
            latency.as_millis().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    fn add_status_count(&self, status: u16) {
        let mut status_counts = lock_unpoisoned(&self.inner.status_counts);
        *status_counts.entry(status).or_insert(0) += 1;
    }

    fn add_error_count(&self, error_key: String) {
        let mut error_counts = lock_unpoisoned(&self.inner.error_counts);
        *error_counts.entry(error_key).or_insert(0) += 1;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics.inner.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}
