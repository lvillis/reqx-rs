use std::collections::{BTreeMap, BTreeSet};
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
    retryable_transport_error_kinds: BTreeSet<TransportErrorKind>,
    retryable_timeout_phases: BTreeSet<TimeoutPhase>,
    retry_on_response_body_read_error: bool,
    status_retry_windows: BTreeMap<u16, usize>,
    transport_retry_windows: BTreeMap<TransportErrorKind, usize>,
    timeout_retry_windows: BTreeMap<TimeoutPhase, usize>,
    response_body_read_retry_window: Option<usize>,
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
            .field(
                "retryable_transport_error_kinds",
                &self.retryable_transport_error_kinds,
            )
            .field("retryable_timeout_phases", &self.retryable_timeout_phases)
            .field(
                "retry_on_response_body_read_error",
                &self.retry_on_response_body_read_error,
            )
            .field("status_retry_windows", &self.status_retry_windows)
            .field("transport_retry_windows", &self.transport_retry_windows)
            .field("timeout_retry_windows", &self.timeout_retry_windows)
            .field(
                "response_body_read_retry_window",
                &self.response_body_read_retry_window,
            )
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
            retryable_transport_error_kinds: default_retryable_transport_error_kinds(),
            retryable_timeout_phases: default_retryable_timeout_phases(),
            retry_on_response_body_read_error: true,
            status_retry_windows: BTreeMap::new(),
            transport_retry_windows: BTreeMap::new(),
            timeout_retry_windows: BTreeMap::new(),
            response_body_read_retry_window: None,
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
            retryable_transport_error_kinds: default_retryable_transport_error_kinds(),
            retryable_timeout_phases: default_retryable_timeout_phases(),
            retry_on_response_body_read_error: true,
            status_retry_windows: BTreeMap::new(),
            transport_retry_windows: BTreeMap::new(),
            timeout_retry_windows: BTreeMap::new(),
            response_body_read_retry_window: None,
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

    pub fn retryable_transport_error_kinds(
        mut self,
        kinds: impl IntoIterator<Item = TransportErrorKind>,
    ) -> Self {
        self.retryable_transport_error_kinds = kinds.into_iter().collect();
        self
    }

    pub fn retryable_timeout_phases(
        mut self,
        phases: impl IntoIterator<Item = TimeoutPhase>,
    ) -> Self {
        self.retryable_timeout_phases = phases.into_iter().collect();
        self
    }

    pub fn retry_on_response_body_read_error(mut self, retry: bool) -> Self {
        self.retry_on_response_body_read_error = retry;
        self
    }

    pub fn status_retry_window(mut self, status: u16, max_attempts: usize) -> Self {
        self.status_retry_windows
            .insert(status, max_attempts.max(1));
        self
    }

    pub fn transport_retry_window(mut self, kind: TransportErrorKind, max_attempts: usize) -> Self {
        self.transport_retry_windows
            .insert(kind, max_attempts.max(1));
        self
    }

    pub fn timeout_retry_window(mut self, phase: TimeoutPhase, max_attempts: usize) -> Self {
        self.timeout_retry_windows
            .insert(phase, max_attempts.max(1));
        self
    }

    pub fn response_body_read_retry_window(mut self, max_attempts: usize) -> Self {
        self.response_body_read_retry_window = Some(max_attempts.max(1));
        self
    }

    pub fn retry_classifier(mut self, retry_classifier: Arc<dyn RetryClassifier>) -> Self {
        self.retry_classifier = Some(retry_classifier);
        self
    }

    pub(crate) fn configured_max_attempts(&self) -> usize {
        self.max_attempts
    }

    fn should_retry_status(&self, status: StatusCode) -> bool {
        self.retryable_status_codes.contains(&status.as_u16())
    }

    pub(crate) fn is_retryable_status(&self, status: StatusCode) -> bool {
        self.should_retry_status(status)
    }

    fn is_within_retry_window(limit: Option<usize>, attempt: usize) -> bool {
        match limit {
            Some(limit) => attempt < limit.max(1),
            None => true,
        }
    }

    pub(crate) fn should_retry_decision(&self, decision: &RetryDecision) -> bool {
        if let Some(retry_classifier) = &self.retry_classifier {
            return retry_classifier.should_retry(decision);
        }
        if let Some(status) = decision.status {
            let window = self.status_retry_windows.get(&status.as_u16()).copied();
            return self.should_retry_status(status)
                && Self::is_within_retry_window(window, decision.attempt);
        }
        if let Some(kind) = decision.transport_error_kind {
            let window = self.transport_retry_windows.get(&kind).copied();
            return self.retryable_transport_error_kinds.contains(&kind)
                && Self::is_within_retry_window(window, decision.attempt);
        }
        if let Some(phase) = decision.timeout_phase {
            let window = self.timeout_retry_windows.get(&phase).copied();
            return self.retryable_timeout_phases.contains(&phase)
                && Self::is_within_retry_window(window, decision.attempt);
        }
        if decision.response_body_read_error {
            return self.retry_on_response_body_read_error
                && Self::is_within_retry_window(
                    self.response_body_read_retry_window,
                    decision.attempt,
                );
        }
        false
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
        let max_backoff_ms = self.max_backoff.as_millis().min(u64::MAX as u128) as u64;

        let jitter_span = ((backoff_ms as f64) * self.jitter_ratio).round().max(1.0) as u64;
        let low = backoff_ms.saturating_sub(jitter_span);
        let high = backoff_ms.saturating_add(jitter_span).max(low);
        let mut rng = rand::rng();
        let sampled_ms = rng.random_range(low..=high).min(max_backoff_ms.max(1));
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

fn default_retryable_transport_error_kinds() -> BTreeSet<TransportErrorKind> {
    [
        TransportErrorKind::Dns,
        TransportErrorKind::Connect,
        TransportErrorKind::Read,
    ]
    .into_iter()
    .collect()
}

fn default_retryable_timeout_phases() -> BTreeSet<TimeoutPhase> {
    [TimeoutPhase::Transport, TimeoutPhase::ResponseBody]
        .into_iter()
        .collect()
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

#[cfg(test)]
mod tests {
    use super::{RetryDecision, RetryPolicy};
    use http::Method;

    #[test]
    fn jittered_backoff_never_exceeds_configured_max_backoff() {
        let policy = RetryPolicy::standard()
            .base_backoff(std::time::Duration::from_millis(100))
            .max_backoff(std::time::Duration::from_millis(120))
            .jitter_ratio(1.0);

        for _ in 0..256 {
            let backoff = policy.backoff_for_retry(3);
            assert!(backoff <= std::time::Duration::from_millis(120));
        }
    }

    #[test]
    fn should_retry_decision_defaults_to_no_retry_for_unclassified_outcome() {
        let policy = RetryPolicy::standard();
        let decision = RetryDecision {
            attempt: 1,
            max_attempts: 3,
            method: Method::GET,
            uri: "https://api.example.com/v1/items".to_owned(),
            status: None,
            transport_error_kind: None,
            timeout_phase: None,
            response_body_read_error: false,
        };

        assert!(!policy.should_retry_decision(&decision));
    }
}
