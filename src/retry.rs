use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};
use rand::RngExt;

use crate::IDEMPOTENCY_KEY_HEADER;
use crate::error::{TimeoutPhase, TransportErrorKind};

#[derive(Clone, Debug)]
pub struct RetryDecision {
    pub attempt: usize,
    pub max_attempts: usize,
    pub method: Method,
    pub uri: String,
    pub status: Option<StatusCode>,
    pub transport_error_kind: Option<TransportErrorKind>,
    pub timeout_phase: Option<TimeoutPhase>,
    pub response_body_read_error: bool,
}

pub trait RetryClassifier: Send + Sync {
    fn should_retry(&self, decision: &RetryDecision) -> bool;
}

pub trait RetryEligibility: Send + Sync {
    fn supports_retry(&self, method: &Method, headers: &HeaderMap) -> bool;
}

#[derive(Default)]
pub struct StrictRetryEligibility;

impl RetryEligibility for StrictRetryEligibility {
    fn supports_retry(&self, method: &Method, headers: &HeaderMap) -> bool {
        request_supports_retry(method, headers)
    }
}

#[derive(Default)]
pub struct PermissiveRetryEligibility;

impl RetryEligibility for PermissiveRetryEligibility {
    fn supports_retry(&self, _method: &Method, _headers: &HeaderMap) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct RetryPolicy {
    max_attempts: usize,
    base_backoff: Duration,
    max_backoff: Duration,
    jitter_ratio: f64,
    retryable_status_codes: BTreeSet<u16>,
    retry_classifier: Option<Arc<dyn RetryClassifier>>,
}

impl std::fmt::Debug for RetryPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetryPolicy")
            .field("max_attempts", &self.max_attempts)
            .field("base_backoff", &self.base_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("jitter_ratio", &self.jitter_ratio)
            .field("retryable_status_codes", &self.retryable_status_codes)
            .finish()
    }
}

impl RetryPolicy {
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
            jitter_ratio: 0.0,
            retryable_status_codes: default_retryable_status_codes(),
            retry_classifier: None,
        }
    }

    pub fn standard() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
            jitter_ratio: 0.2,
            retryable_status_codes: default_retryable_status_codes(),
            retry_classifier: None,
        }
    }

    pub fn max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn base_backoff(mut self, base_backoff: Duration) -> Self {
        self.base_backoff = base_backoff.max(Duration::from_millis(1));
        if self.max_backoff < self.base_backoff {
            self.max_backoff = self.base_backoff;
        }
        self
    }

    pub fn max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff.max(self.base_backoff);
        self
    }

    pub fn jitter_ratio(mut self, jitter_ratio: f64) -> Self {
        self.jitter_ratio = jitter_ratio.clamp(0.0, 1.0);
        self
    }

    pub fn retryable_status_codes(mut self, codes: impl IntoIterator<Item = u16>) -> Self {
        self.retryable_status_codes = codes.into_iter().collect();
        self
    }

    pub fn retry_classifier(mut self, retry_classifier: Arc<dyn RetryClassifier>) -> Self {
        self.retry_classifier = Some(retry_classifier);
        self
    }

    pub(crate) fn max_attempts_value(&self) -> usize {
        self.max_attempts
    }

    fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retryable_status_codes.contains(&status.as_u16())
    }

    pub(crate) fn should_retry_decision(&self, decision: &RetryDecision) -> bool {
        if let Some(retry_classifier) = &self.retry_classifier {
            return retry_classifier.should_retry(decision);
        }
        match decision.status {
            Some(status) => self.should_retry_status(status),
            None => true,
        }
    }

    pub(crate) fn backoff_for_retry(&self, retry_index: usize) -> Duration {
        let capped_exponent = retry_index.saturating_sub(1).min(31) as u32;
        let multiplier = 1_u128 << capped_exponent;
        let base_ms = self.base_backoff.as_millis().max(1);
        let max_ms = self.max_backoff.as_millis().max(base_ms);
        let delay_ms = base_ms
            .saturating_mul(multiplier)
            .min(max_ms)
            .min(u64::MAX as u128) as u64;
        self.apply_jitter(Duration::from_millis(delay_ms))
    }

    fn apply_jitter(&self, backoff: Duration) -> Duration {
        if self.jitter_ratio <= f64::EPSILON {
            return backoff;
        }

        let backoff_ms = backoff.as_millis().min(u64::MAX as u128) as u64;
        if backoff_ms <= 1 {
            return backoff;
        }

        let jitter_span = ((backoff_ms as f64) * self.jitter_ratio).round().max(1.0) as u64;
        let low = backoff_ms.saturating_sub(jitter_span);
        let high = backoff_ms.saturating_add(jitter_span).max(low);
        let mut rng = rand::rng();
        let sampled_ms = rng.random_range(low..=high);
        Duration::from_millis(sampled_ms)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

fn default_retryable_status_codes() -> BTreeSet<u16> {
    [429_u16, 500, 502, 503, 504].into_iter().collect()
}

pub(crate) fn request_supports_retry(method: &Method, headers: &HeaderMap) -> bool {
    is_method_idempotent(method) || headers.get(IDEMPOTENCY_KEY_HEADER).is_some()
}

fn is_method_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS | Method::TRACE
    )
}
