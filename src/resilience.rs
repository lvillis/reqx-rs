use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::extensions::Clock;
use crate::util::lock_unpoisoned;

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
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window.max(Duration::from_millis(1));
        self
    }

    /// Sets the retry allowance as a fraction of recent successful requests.
    pub fn retry_ratio(mut self, retry_ratio: f64) -> Self {
        self.retry_ratio = retry_ratio.clamp(0.0, 1.0);
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
                active_requests, ..
            } => {
                if *active_requests >= self.policy.half_open_max_requests.max(1) {
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
                if *successful_requests >= self.policy.half_open_success_threshold.max(1) {
                    *state = CircuitState::Closed {
                        consecutive_failures: 0,
                    };
                }
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
                if *consecutive_failures >= self.policy.failure_threshold.max(1) {
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
        self.completed = true;
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
    pub fn decrease_ratio(mut self, decrease_ratio: f64) -> Self {
        self.decrease_ratio = decrease_ratio.clamp(0.1, 0.99);
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
        if self.min_limit > self.max_limit {
            return Err(Error::InvalidAdaptiveConcurrencyPolicy {
                min_limit: self.min_limit,
                initial_limit: self.initial_limit,
                max_limit: self.max_limit,
                message: "min_limit must be <= max_limit",
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
}

impl Default for AdaptiveConcurrencyPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl AdaptiveConcurrencyState {
    pub(crate) fn new(policy: AdaptiveConcurrencyPolicy) -> Self {
        let min_limit = policy.configured_min_limit().max(1);
        let max_limit = policy.configured_max_limit().max(min_limit);
        let initial_limit = policy
            .configured_initial_limit()
            .max(1)
            .clamp(min_limit, max_limit);
        Self {
            in_flight: 0,
            current_limit: initial_limit,
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
        success: bool,
        latency: Duration,
    ) {
        self.in_flight = self.in_flight.saturating_sub(1);

        let latency_ms = latency.as_secs_f64() * 1000.0;
        if self.ewma_latency_ms <= f64::EPSILON {
            self.ewma_latency_ms = latency_ms;
        } else {
            self.ewma_latency_ms = self.ewma_latency_ms * 0.8 + latency_ms * 0.2;
        }

        let threshold_ms = policy.configured_high_latency_threshold().as_secs_f64() * 1000.0;
        let should_decrease = !success || self.ewma_latency_ms > threshold_ms;
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

    use super::{CircuitBreaker, CircuitBreakerPolicy, RetryBudget, RetryBudgetPolicy};
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
    fn retry_budget_zero_window_is_clamped() {
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
}
