use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::extensions::Clock;
use crate::util::{clamp_f64_or_fallback, lock_unpoisoned, normalize_usize_at_least_one};

#[derive(Clone, Copy, Debug, PartialEq)]
/// Limits how many retries can be spent relative to recent successful traffic.
pub struct RetryBudgetPolicy {
    window: Duration,
    retry_ratio: f64,
    min_retries_per_window: usize,
}

impl RetryBudgetPolicy {
    /// Returns the default retry budget used for SDK traffic.
    pub const fn standard() -> Self {
        Self {
            window: Duration::from_secs(10),
            retry_ratio: 0.2,
            min_retries_per_window: 3,
        }
    }

    /// Returns a policy that effectively disables retry budget enforcement.
    pub const fn disabled() -> Self {
        Self {
            window: Duration::from_secs(1),
            retry_ratio: 1.0,
            min_retries_per_window: usize::MAX,
        }
    }

    /// Sets the rolling window used to account for successes and retries.
    ///
    /// A zero duration is rejected by client builders.
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Sets the retry allowance as a fraction of recent successful requests.
    ///
    /// Values must be finite and in the inclusive range `0.0..=1.0`.
    pub fn retry_ratio(mut self, retry_ratio: f64) -> Self {
        self.retry_ratio = retry_ratio;
        self
    }

    /// Sets the minimum number of retries allowed in each accounting window.
    pub const fn min_retries_per_window(mut self, min_retries_per_window: usize) -> Self {
        self.min_retries_per_window = min_retries_per_window;
        self
    }

    pub(crate) const fn configured_window(self) -> Duration {
        self.window
    }

    pub(crate) fn configured_retry_ratio(self) -> f64 {
        self.retry_ratio
    }

    pub(crate) const fn configured_min_retries_per_window(self) -> usize {
        self.min_retries_per_window
    }

    pub(crate) fn validate(self) -> crate::Result<()> {
        if self.window.is_zero() {
            return Err(self.invalid_policy("window must be greater than zero"));
        }
        if !self.retry_ratio.is_finite() || !(0.0..=1.0).contains(&self.retry_ratio) {
            return Err(self.invalid_policy("retry_ratio must be finite and between 0.0 and 1.0"));
        }
        Ok(())
    }

    fn invalid_policy(self, message: &'static str) -> Error {
        Error::InvalidRetryBudgetPolicy {
            window_ms: self.window.as_millis(),
            retry_ratio: self.retry_ratio,
            min_retries_per_window: self.min_retries_per_window,
            message,
        }
    }

    fn normalize_for_runtime(self) -> Self {
        Self {
            window: self.window.max(Duration::from_millis(1)),
            retry_ratio: clamp_f64_or_fallback(self.retry_ratio, 0.0, 1.0, 0.0),
            min_retries_per_window: self.min_retries_per_window,
        }
    }
}

impl Default for RetryBudgetPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

struct RetryBudgetState {
    window_started_at: Instant,
    requests_succeeded: usize,
    retries_consumed: usize,
}

pub(crate) struct RetryBudget {
    policy: RetryBudgetPolicy,
    clock: Arc<dyn Clock>,
    state: Mutex<RetryBudgetState>,
}

impl RetryBudget {
    pub(crate) fn new(policy: RetryBudgetPolicy, clock: Arc<dyn Clock>) -> Self {
        let policy = policy.normalize_for_runtime();
        let window_started_at = clock.now_monotonic();
        Self {
            policy,
            clock,
            state: Mutex::new(RetryBudgetState {
                window_started_at,
                requests_succeeded: 0,
                retries_consumed: 0,
            }),
        }
    }

    pub(crate) fn record_success(&self) {
        let mut state = lock_unpoisoned(&self.state);
        refresh_retry_budget_window(&self.policy, &mut state, self.clock.as_ref());
        state.requests_succeeded = state.requests_succeeded.saturating_add(1);
    }

    pub(crate) fn try_consume_retry(&self) -> bool {
        let mut state = lock_unpoisoned(&self.state);
        refresh_retry_budget_window(&self.policy, &mut state, self.clock.as_ref());
        let dynamic_allowance = (state.requests_succeeded as f64
            * self.policy.configured_retry_ratio())
        .floor() as usize;
        let total_allowance =
            dynamic_allowance.saturating_add(self.policy.configured_min_retries_per_window());
        if state.retries_consumed >= total_allowance {
            return false;
        }
        state.retries_consumed = state.retries_consumed.saturating_add(1);
        true
    }
}

impl std::fmt::Debug for RetryBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetryBudget")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

fn refresh_retry_budget_window(
    policy: &RetryBudgetPolicy,
    state: &mut RetryBudgetState,
    clock: &dyn Clock,
) {
    let now = clock.now_monotonic();
    if now.saturating_duration_since(state.window_started_at) >= policy.configured_window() {
        state.window_started_at = now;
        state.requests_succeeded = 0;
        state.retries_consumed = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Circuit breaker thresholds for fast-failing unhealthy upstreams.
pub struct CircuitBreakerPolicy {
    failure_threshold: usize,
    open_timeout: Duration,
    half_open_max_requests: usize,
    half_open_success_threshold: usize,
}

impl CircuitBreakerPolicy {
    /// Returns the default circuit breaker settings.
    pub const fn standard() -> Self {
        Self {
            failure_threshold: 5,
            open_timeout: Duration::from_secs(10),
            half_open_max_requests: 2,
            half_open_success_threshold: 2,
        }
    }

    /// Sets how many consecutive failures open the circuit.
    pub const fn failure_threshold(mut self, failure_threshold: usize) -> Self {
        self.failure_threshold = failure_threshold;
        self
    }

    /// Sets how long the circuit stays open before probing again.
    pub const fn open_timeout(mut self, open_timeout: Duration) -> Self {
        self.open_timeout = open_timeout;
        self
    }

    /// Sets the maximum concurrent probe requests allowed while half-open.
    pub const fn half_open_max_requests(mut self, half_open_max_requests: usize) -> Self {
        self.half_open_max_requests = half_open_max_requests;
        self
    }

    /// Sets how many successful probes close the circuit again.
    pub const fn half_open_success_threshold(mut self, half_open_success_threshold: usize) -> Self {
        self.half_open_success_threshold = half_open_success_threshold;
        self
    }

    pub(crate) fn validate(self) -> crate::Result<()> {
        if self.failure_threshold == 0 {
            return Err(Error::InvalidCircuitBreakerPolicy {
                failure_threshold: self.failure_threshold,
                open_timeout_ms: self.open_timeout.as_millis(),
                half_open_max_requests: self.half_open_max_requests,
                half_open_success_threshold: self.half_open_success_threshold,
                message: "failure_threshold must be >= 1",
            });
        }
        if self.open_timeout.is_zero() {
            return Err(Error::InvalidCircuitBreakerPolicy {
                failure_threshold: self.failure_threshold,
                open_timeout_ms: self.open_timeout.as_millis(),
                half_open_max_requests: self.half_open_max_requests,
                half_open_success_threshold: self.half_open_success_threshold,
                message: "open_timeout must be >= 1ms",
            });
        }
        if self.half_open_max_requests == 0 {
            return Err(Error::InvalidCircuitBreakerPolicy {
                failure_threshold: self.failure_threshold,
                open_timeout_ms: self.open_timeout.as_millis(),
                half_open_max_requests: self.half_open_max_requests,
                half_open_success_threshold: self.half_open_success_threshold,
                message: "half_open_max_requests must be >= 1",
            });
        }
        if self.half_open_success_threshold == 0 {
            return Err(Error::InvalidCircuitBreakerPolicy {
                failure_threshold: self.failure_threshold,
                open_timeout_ms: self.open_timeout.as_millis(),
                half_open_max_requests: self.half_open_max_requests,
                half_open_success_threshold: self.half_open_success_threshold,
                message: "half_open_success_threshold must be >= 1",
            });
        }
        Ok(())
    }

    fn normalize_for_runtime(self) -> Self {
        Self {
            failure_threshold: normalize_usize_at_least_one(self.failure_threshold),
            open_timeout: self.open_timeout.max(Duration::from_millis(1)),
            half_open_max_requests: normalize_usize_at_least_one(self.half_open_max_requests),
            half_open_success_threshold: normalize_usize_at_least_one(
                self.half_open_success_threshold,
            ),
        }
    }
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CircuitAttemptKind {
    Closed,
    HalfOpen,
}

enum CircuitState {
    Closed {
        consecutive_failures: usize,
    },
    Open {
        opened_at: Instant,
    },
    HalfOpen {
        active_requests: usize,
        successful_requests: usize,
    },
}

pub(crate) struct CircuitBreaker {
    policy: CircuitBreakerPolicy,
    clock: Arc<dyn Clock>,
    state: Mutex<CircuitState>,
}

impl CircuitBreaker {
    pub(crate) fn new(policy: CircuitBreakerPolicy, clock: Arc<dyn Clock>) -> Self {
        let policy = policy.normalize_for_runtime();
        Self {
            policy,
            clock,
            state: Mutex::new(CircuitState::Closed {
                consecutive_failures: 0,
            }),
        }
    }

    pub(crate) fn begin(self: &Arc<Self>) -> Result<CircuitAttempt, Duration> {
        let mut state = lock_unpoisoned(&self.state);
        let now = self.clock.now_monotonic();
        match &mut *state {
            CircuitState::Closed { .. } => Ok(CircuitAttempt {
                breaker: Arc::clone(self),
                kind: CircuitAttemptKind::Closed,
                completed: false,
            }),
            CircuitState::Open { opened_at } => {
                let elapsed = now.saturating_duration_since(*opened_at);
                if elapsed >= self.policy.open_timeout {
                    *state = CircuitState::HalfOpen {
                        active_requests: 1,
                        successful_requests: 0,
                    };
                    return Ok(CircuitAttempt {
                        breaker: Arc::clone(self),
                        kind: CircuitAttemptKind::HalfOpen,
                        completed: false,
                    });
                }
                Err(self.policy.open_timeout - elapsed)
            }
            CircuitState::HalfOpen {
                active_requests,
                successful_requests,
            } => {
                if *active_requests >= self.policy.half_open_max_requests
                    || *successful_requests >= self.policy.half_open_success_threshold
                {
                    return Err(Duration::from_millis(0));
                }
                *active_requests = active_requests.saturating_add(1);
                Ok(CircuitAttempt {
                    breaker: Arc::clone(self),
                    kind: CircuitAttemptKind::HalfOpen,
                    completed: false,
                })
            }
        }
    }

    fn record_success(&self, kind: CircuitAttemptKind) {
        let mut state = lock_unpoisoned(&self.state);
        match (&mut *state, kind) {
            (
                CircuitState::Closed {
                    consecutive_failures,
                },
                CircuitAttemptKind::Closed,
            ) => {
                *consecutive_failures = 0;
            }
            (
                CircuitState::HalfOpen {
                    active_requests,
                    successful_requests,
                },
                CircuitAttemptKind::HalfOpen,
            ) => {
                *active_requests = active_requests.saturating_sub(1);
                *successful_requests = successful_requests.saturating_add(1);
                close_half_open_if_recovered(&mut state, self.policy.half_open_success_threshold);
            }
            _ => {}
        }
    }

    fn record_failure(&self, kind: CircuitAttemptKind) {
        let mut state = lock_unpoisoned(&self.state);
        match (&mut *state, kind) {
            (
                CircuitState::Closed {
                    consecutive_failures,
                },
                CircuitAttemptKind::Closed,
            ) => {
                *consecutive_failures = consecutive_failures.saturating_add(1);
                if *consecutive_failures >= self.policy.failure_threshold {
                    *state = CircuitState::Open {
                        opened_at: self.clock.now_monotonic(),
                    };
                }
            }
            (
                CircuitState::HalfOpen {
                    active_requests, ..
                },
                CircuitAttemptKind::HalfOpen,
            ) => {
                *active_requests = active_requests.saturating_sub(1);
                *state = CircuitState::Open {
                    opened_at: self.clock.now_monotonic(),
                };
            }
            _ => {}
        }
    }

    fn record_cancel(&self, kind: CircuitAttemptKind) {
        let mut state = lock_unpoisoned(&self.state);
        if let (
            CircuitState::HalfOpen {
                active_requests, ..
            },
            CircuitAttemptKind::HalfOpen,
        ) = (&mut *state, kind)
        {
            *active_requests = active_requests.saturating_sub(1);
            close_half_open_if_recovered(&mut state, self.policy.half_open_success_threshold);
        }
    }
}

fn close_half_open_if_recovered(state: &mut CircuitState, half_open_success_threshold: usize) {
    if let CircuitState::HalfOpen {
        active_requests,
        successful_requests,
    } = state
        && *active_requests == 0
        && *successful_requests >= half_open_success_threshold
    {
        *state = CircuitState::Closed {
            consecutive_failures: 0,
        };
    }
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CircuitBreaker")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

pub(crate) struct CircuitAttempt {
    breaker: Arc<CircuitBreaker>,
    kind: CircuitAttemptKind,
    completed: bool,
}

impl CircuitAttempt {
    pub(crate) fn mark_success(mut self) {
        self.breaker.record_success(self.kind);
        self.completed = true;
    }

    pub(crate) fn mark_failure(mut self) {
        self.breaker.record_failure(self.kind);
        self.completed = true;
    }

    pub(crate) fn cancel(mut self) {
        self.breaker.record_cancel(self.kind);
        self.completed = true;
    }
}

impl crate::core::execution::AttemptOutcome for CircuitAttempt {
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

impl Drop for CircuitAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.breaker.record_failure(self.kind);
            self.completed = true;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
/// Adaptive concurrency limits based on observed request latency.
pub struct AdaptiveConcurrencyPolicy {
    min_limit: usize,
    initial_limit: usize,
    max_limit: usize,
    increase_step: usize,
    decrease_ratio: f64,
    high_latency_threshold: Duration,
}

#[derive(Debug)]
pub(crate) struct AdaptiveConcurrencyState {
    in_flight: usize,
    current_limit: usize,
    ewma_latency_ms: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdaptiveConcurrencyOutcome {
    Success,
    Failure,
}

impl AdaptiveConcurrencyPolicy {
    /// Returns the default adaptive concurrency settings.
    pub const fn standard() -> Self {
        Self {
            min_limit: 1,
            initial_limit: 8,
            max_limit: 64,
            increase_step: 1,
            decrease_ratio: 0.8,
            high_latency_threshold: Duration::from_millis(300),
        }
    }

    /// Sets the minimum in-flight request limit.
    pub const fn min_limit(mut self, min_limit: usize) -> Self {
        self.min_limit = min_limit;
        self
    }

    /// Sets the starting in-flight request limit.
    pub const fn initial_limit(mut self, initial_limit: usize) -> Self {
        self.initial_limit = initial_limit;
        self
    }

    /// Sets the maximum in-flight request limit.
    pub const fn max_limit(mut self, max_limit: usize) -> Self {
        self.max_limit = max_limit;
        self
    }

    /// Sets how much to raise the limit after a healthy control interval.
    pub const fn increase_step(mut self, increase_step: usize) -> Self {
        self.increase_step = increase_step;
        self
    }

    /// Sets the multiplicative backoff applied after high-latency samples.
    ///
    /// Values must be finite and in the range `0.0..1.0`.
    pub fn decrease_ratio(mut self, decrease_ratio: f64) -> Self {
        self.decrease_ratio = decrease_ratio;
        self
    }

    /// Sets the latency threshold that triggers a limit decrease.
    pub const fn high_latency_threshold(mut self, high_latency_threshold: Duration) -> Self {
        self.high_latency_threshold = high_latency_threshold;
        self
    }

    pub(crate) fn validate(self) -> crate::Result<()> {
        if self.min_limit == 0 {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "min_limit must be >= 1",
            });
        }
        if self.max_limit == 0 {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "max_limit must be >= 1",
            });
        }
        if self.initial_limit == 0 {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "initial_limit must be >= 1",
            });
        }
        if self.increase_step == 0 {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "increase_step must be >= 1",
            });
        }
        if self.high_latency_threshold.is_zero() {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "high_latency_threshold must be >= 1ms",
            });
        }
        if !self.decrease_ratio.is_finite() || !(0.0..1.0).contains(&self.decrease_ratio) {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "decrease_ratio must be finite and between 0.0 and 1.0",
            });
        }
        if self.min_limit > self.max_limit {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "min_limit must be <= max_limit",
            });
        }
        if self.initial_limit < self.min_limit {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "initial_limit must be >= min_limit",
            });
        }
        if self.initial_limit > self.max_limit {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "initial_limit must be <= max_limit",
            });
        }
        Ok(())
    }

    pub(crate) const fn configured_min_limit(self) -> usize {
        self.min_limit
    }

    pub(crate) const fn configured_initial_limit(self) -> usize {
        self.initial_limit
    }

    pub(crate) const fn configured_max_limit(self) -> usize {
        self.max_limit
    }

    pub(crate) const fn configured_increase_step(self) -> usize {
        self.increase_step
    }

    pub(crate) fn configured_decrease_ratio(self) -> f64 {
        self.decrease_ratio
    }

    pub(crate) const fn configured_high_latency_threshold(self) -> Duration {
        self.high_latency_threshold
    }

    pub(crate) fn normalize_for_runtime(self) -> Self {
        let min_limit = normalize_usize_at_least_one(self.min_limit);
        let max_limit = self.max_limit.max(min_limit);
        let initial_limit =
            normalize_usize_at_least_one(self.initial_limit).clamp(min_limit, max_limit);

        Self {
            min_limit,
            initial_limit,
            max_limit,
            increase_step: normalize_usize_at_least_one(self.increase_step),
            decrease_ratio: if self.decrease_ratio.is_finite()
                && (0.0..1.0).contains(&self.decrease_ratio)
            {
                self.decrease_ratio
            } else {
                Self::standard().decrease_ratio
            },
            high_latency_threshold: self.high_latency_threshold.max(Duration::from_millis(1)),
        }
    }
}

impl Default for AdaptiveConcurrencyPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl AdaptiveConcurrencyState {
    pub(crate) fn new(policy: AdaptiveConcurrencyPolicy) -> Self {
        let policy = policy.normalize_for_runtime();
        Self {
            in_flight: 0,
            current_limit: policy.configured_initial_limit(),
            ewma_latency_ms: 0.0,
        }
    }

    pub(crate) fn try_acquire(&mut self) -> bool {
        if self.in_flight >= self.current_limit {
            return false;
        }
        self.in_flight = self.in_flight.saturating_add(1);
        true
    }

    pub(crate) fn release_and_record(
        &mut self,
        policy: AdaptiveConcurrencyPolicy,
        outcome: AdaptiveConcurrencyOutcome,
        latency: Duration,
    ) {
        let policy = policy.normalize_for_runtime();
        self.in_flight = self.in_flight.saturating_sub(1);

        let latency_ms = latency.as_secs_f64() * 1000.0;
        if self.ewma_latency_ms <= f64::EPSILON {
            self.ewma_latency_ms = latency_ms;
        } else {
            self.ewma_latency_ms = self.ewma_latency_ms * 0.8 + latency_ms * 0.2;
        }

        let threshold_ms = policy.configured_high_latency_threshold().as_secs_f64() * 1000.0;
        let should_decrease = matches!(outcome, AdaptiveConcurrencyOutcome::Failure)
            || self.ewma_latency_ms > threshold_ms;
        if should_decrease {
            let decreased =
                (self.current_limit as f64 * policy.configured_decrease_ratio()).floor() as usize;
            self.current_limit = decreased.max(policy.configured_min_limit());
        } else {
            self.current_limit = self
                .current_limit
                .saturating_add(policy.configured_increase_step())
                .min(policy.configured_max_limit());
        }
    }

    pub(crate) fn release_without_record(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant, SystemTime};

    use super::{
        AdaptiveConcurrencyOutcome, AdaptiveConcurrencyPolicy, AdaptiveConcurrencyState,
        CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy,
    };
    use crate::error::Error;
    use crate::extensions::Clock;

    #[derive(Debug)]
    struct TestClock {
        base_monotonic: Instant,
        base_system: SystemTime,
        elapsed: Mutex<Duration>,
    }

    impl Default for TestClock {
        fn default() -> Self {
            Self {
                base_monotonic: Instant::now(),
                base_system: SystemTime::UNIX_EPOCH,
                elapsed: Mutex::new(Duration::ZERO),
            }
        }
    }

    impl TestClock {
        fn advance(&self, duration: Duration) {
            let mut elapsed = self.elapsed.lock().expect("test clock mutex poisoned");
            *elapsed = elapsed.saturating_add(duration);
        }

        fn elapsed(&self) -> Duration {
            *self.elapsed.lock().expect("test clock mutex poisoned")
        }
    }

    impl Clock for TestClock {
        fn now_system(&self) -> SystemTime {
            self.base_system + self.elapsed()
        }

        fn now_monotonic(&self) -> Instant {
            self.base_monotonic + self.elapsed()
        }
    }

    #[test]
    fn retry_budget_enforces_minimum_retries_per_window() {
        let clock = Arc::new(TestClock::default());
        let budget = RetryBudget::new(
            RetryBudgetPolicy::standard()
                .window(Duration::from_millis(20))
                .retry_ratio(0.0)
                .min_retries_per_window(1),
            clock.clone(),
        );

        assert!(budget.try_consume_retry());
        assert!(!budget.try_consume_retry());

        clock.advance(Duration::from_millis(25));
        assert!(budget.try_consume_retry());
    }

    #[test]
    fn retry_budget_uses_success_ratio_for_allowance() {
        let clock = Arc::new(TestClock::default());
        let budget = RetryBudget::new(
            RetryBudgetPolicy::standard()
                .window(Duration::from_secs(1))
                .retry_ratio(0.5)
                .min_retries_per_window(0),
            clock,
        );

        assert!(!budget.try_consume_retry());
        budget.record_success();
        budget.record_success();

        assert!(budget.try_consume_retry());
        assert!(!budget.try_consume_retry());
    }

    #[test]
    fn retry_budget_runtime_normalizes_zero_window_defensively() {
        let clock = Arc::new(TestClock::default());
        let budget = RetryBudget::new(
            RetryBudgetPolicy::standard()
                .window(Duration::ZERO)
                .retry_ratio(0.0)
                .min_retries_per_window(1),
            clock,
        );

        assert!(budget.try_consume_retry());
        assert!(
            !budget.try_consume_retry(),
            "zero window must not reset budget on every check"
        );
    }

    #[test]
    fn retry_budget_validate_rejects_nan_retry_ratio() {
        let policy = RetryBudgetPolicy::standard().retry_ratio(f64::NAN);

        match policy.validate() {
            Err(Error::InvalidRetryBudgetPolicy { retry_ratio, .. }) => {
                assert!(retry_ratio.is_nan());
            }
            other => panic!("unexpected validation result: {other:?}"),
        }
    }

    #[test]
    fn circuit_breaker_opens_then_recovers_after_half_open_success() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(2)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
            clock.clone(),
        ));

        drop(
            breaker
                .begin()
                .expect("first closed attempt should be allowed"),
        );
        drop(
            breaker
                .begin()
                .expect("second closed attempt should be allowed"),
        );

        assert!(
            breaker.begin().is_err(),
            "breaker should be open after reaching failure threshold"
        );

        clock.advance(Duration::from_millis(25));
        let half_open_attempt = breaker
            .begin()
            .expect("breaker should transition to half-open after open timeout");
        half_open_attempt.mark_success();

        assert!(
            breaker.begin().is_ok(),
            "breaker should close again after successful half-open request"
        );
    }

    #[test]
    fn circuit_breaker_zero_thresholds_are_normalized_at_runtime() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(0)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(0)
                .half_open_success_threshold(0),
            clock.clone(),
        ));

        breaker
            .begin()
            .expect("closed attempt should be allowed")
            .mark_failure();
        assert!(
            breaker.begin().is_err(),
            "zero failure threshold should be normalized to one"
        );

        clock.advance(Duration::from_millis(25));
        let half_open_attempt = breaker.begin().expect("half-open probe should be allowed");
        assert!(
            breaker.begin().is_err(),
            "zero half-open concurrency should be normalized to one"
        );
        half_open_attempt.mark_success();

        assert!(
            breaker.begin().is_ok(),
            "zero half-open success threshold should be normalized to one"
        );
    }

    #[test]
    fn circuit_breaker_validate_rejects_zero_failure_threshold() {
        let policy = CircuitBreakerPolicy::standard().failure_threshold(0);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn circuit_breaker_validate_rejects_zero_open_timeout() {
        let policy = CircuitBreakerPolicy::standard().open_timeout(Duration::ZERO);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn circuit_breaker_validate_rejects_zero_half_open_max_requests() {
        let policy = CircuitBreakerPolicy::standard().half_open_max_requests(0);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn circuit_breaker_validate_rejects_zero_half_open_success_threshold() {
        let policy = CircuitBreakerPolicy::standard().half_open_success_threshold(0);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn circuit_breaker_limits_half_open_concurrency() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
            clock.clone(),
        ));

        drop(breaker.begin().expect("closed attempt should be allowed"));
        clock.advance(Duration::from_millis(25));

        let half_open_attempt = breaker
            .begin()
            .expect("breaker should allow one half-open request");
        assert!(
            breaker.begin().is_err(),
            "breaker should reject extra half-open concurrency"
        );

        half_open_attempt.mark_success();
        assert!(
            breaker.begin().is_ok(),
            "breaker should allow requests again after half-open success"
        );
    }

    #[test]
    fn circuit_breaker_cancel_releases_half_open_slot() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(1)
                .half_open_success_threshold(1),
            clock.clone(),
        ));

        breaker
            .begin()
            .expect("closed attempt should be allowed")
            .mark_failure();
        clock.advance(Duration::from_millis(25));

        let half_open_attempt = breaker
            .begin()
            .expect("breaker should allow one half-open request");
        assert!(
            breaker.begin().is_err(),
            "half-open request should occupy the only probe slot"
        );

        half_open_attempt.cancel();

        let replacement_attempt = breaker
            .begin()
            .expect("cancelled half-open request should release the probe slot");
        replacement_attempt.mark_success();
        assert!(
            breaker.begin().is_ok(),
            "breaker should allow requests again after replacement probe succeeds"
        );
    }

    #[test]
    fn circuit_breaker_does_not_ignore_late_half_open_failure_after_success_threshold() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(2)
                .half_open_success_threshold(1),
            clock.clone(),
        ));

        breaker
            .begin()
            .expect("closed attempt should be allowed")
            .mark_failure();
        clock.advance(Duration::from_millis(25));

        let first_probe = breaker.begin().expect("first half-open probe should start");
        let second_probe = breaker
            .begin()
            .expect("second half-open probe should start");

        first_probe.mark_success();
        assert!(
            breaker.begin().is_err(),
            "breaker should wait for active half-open probes before closing"
        );

        second_probe.mark_failure();
        assert!(
            breaker.begin().is_err(),
            "late half-open failure should reopen the circuit"
        );
    }

    #[test]
    fn circuit_breaker_closes_when_success_threshold_met_and_pending_probe_cancels() {
        let clock = Arc::new(TestClock::default());
        let breaker = Arc::new(CircuitBreaker::new(
            CircuitBreakerPolicy::standard()
                .failure_threshold(1)
                .open_timeout(Duration::from_millis(20))
                .half_open_max_requests(2)
                .half_open_success_threshold(1),
            clock.clone(),
        ));

        breaker
            .begin()
            .expect("closed attempt should be allowed")
            .mark_failure();
        clock.advance(Duration::from_millis(25));

        let successful_probe = breaker.begin().expect("first half-open probe should start");
        let cancelled_probe = breaker
            .begin()
            .expect("second half-open probe should start");

        successful_probe.mark_success();
        cancelled_probe.cancel();

        assert!(
            breaker.begin().is_ok(),
            "breaker should close after successful probes complete and cancellations drain"
        );
    }

    #[test]
    fn adaptive_concurrency_validate_rejects_nan_decrease_ratio() {
        let policy = AdaptiveConcurrencyPolicy::standard().decrease_ratio(f64::NAN);

        match policy.validate() {
            Err(Error::InvalidAdaptiveConcurrencyPolicy { message, .. }) => {
                assert_eq!(
                    message,
                    "decrease_ratio must be finite and between 0.0 and 1.0"
                );
            }
            other => panic!("unexpected validation result: {other:?}"),
        }
    }

    #[test]
    fn adaptive_concurrency_runtime_preserves_valid_small_decrease_ratio() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(20)
            .max_limit(20)
            .decrease_ratio(0.05);
        let mut state = AdaptiveConcurrencyState::new(policy);

        assert!(state.try_acquire());
        state.release_and_record(policy, AdaptiveConcurrencyOutcome::Failure, Duration::ZERO);

        assert_eq!(state.current_limit, 1);
    }

    #[test]
    fn adaptive_concurrency_validate_rejects_initial_limit_outside_bounds() {
        let below_min = AdaptiveConcurrencyPolicy::standard()
            .min_limit(4)
            .initial_limit(3)
            .max_limit(8);
        let above_max = AdaptiveConcurrencyPolicy::standard()
            .min_limit(2)
            .initial_limit(9)
            .max_limit(8);

        assert!(below_min.validate().is_err());
        assert!(above_max.validate().is_err());
    }

    #[test]
    fn adaptive_concurrency_validate_rejects_zero_increase_step() {
        let policy = AdaptiveConcurrencyPolicy::standard().increase_step(0);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn adaptive_concurrency_validate_rejects_zero_high_latency_threshold() {
        let policy = AdaptiveConcurrencyPolicy::standard().high_latency_threshold(Duration::ZERO);

        assert!(policy.validate().is_err());
    }

    #[test]
    fn adaptive_concurrency_release_uses_normalized_policy() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(0)
            .initial_limit(0)
            .max_limit(0);
        let mut state = AdaptiveConcurrencyState::new(policy);

        assert!(
            state.try_acquire(),
            "runtime normalization should allow the first request"
        );
        state.release_and_record(policy, AdaptiveConcurrencyOutcome::Success, Duration::ZERO);

        assert!(
            state.try_acquire(),
            "release path should not collapse the normalized limit back to zero"
        );
    }

    #[test]
    fn adaptive_concurrency_release_normalizes_zero_increase_step() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(1)
            .max_limit(3)
            .increase_step(0);
        let mut state = AdaptiveConcurrencyState::new(policy);

        assert!(state.try_acquire());
        state.release_and_record(policy, AdaptiveConcurrencyOutcome::Success, Duration::ZERO);

        assert!(state.try_acquire());
        assert!(
            state.try_acquire(),
            "runtime normalization should let successful samples grow the limit"
        );
    }

    #[test]
    fn adaptive_concurrency_release_normalizes_zero_high_latency_threshold() {
        let policy = AdaptiveConcurrencyPolicy::standard()
            .min_limit(1)
            .initial_limit(1)
            .max_limit(3)
            .high_latency_threshold(Duration::ZERO);
        let mut state = AdaptiveConcurrencyState::new(policy);

        assert!(state.try_acquire());
        state.release_and_record(
            policy,
            AdaptiveConcurrencyOutcome::Success,
            Duration::from_millis(1),
        );

        assert!(state.try_acquire());
        assert!(
            state.try_acquire(),
            "runtime normalization should not classify the minimum threshold sample as high latency"
        );
    }
}
