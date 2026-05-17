use std::time::Duration;

use crate::error::Error;
use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::rate_limit::RateLimitPolicy;
use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy};
use crate::retry::RetryPolicy;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Preset transport defaults tuned for common SDK traffic patterns.
pub enum ClientProfile {
    #[default]
    /// Balanced defaults for general SDK API traffic.
    StandardSdk,
    /// Lower timeouts and lighter retries for latency-sensitive calls.
    LowLatency,
    /// Larger buffers and wider budgets for bulk throughput.
    HighThroughput,
}

#[derive(Clone, Debug)]
pub(crate) struct ProfileDefaults {
    pub request_timeout: Duration,
    pub total_timeout: Option<Duration>,
    pub retry_policy: RetryPolicy,
    pub max_response_body_bytes: usize,
    pub redirect_policy: RedirectPolicy,
    pub status_policy: StatusPolicy,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientTimeoutConfig {
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) connect_timeout: Duration,
}

impl ClientTimeoutConfig {
    pub(crate) fn validate(self) -> crate::Result<()> {
        validate_timeout_config(
            self.request_timeout,
            self.total_timeout,
            Some(self.connect_timeout),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RequestTimeoutConfig {
    pub(crate) request_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
}

impl RequestTimeoutConfig {
    pub(crate) fn validate(self) -> crate::Result<()> {
        validate_timeout_config(self.request_timeout, self.total_timeout, None)
    }
}

fn validate_timeout_config(
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
) -> crate::Result<()> {
    if request_timeout.is_zero() {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "request_timeout must be greater than zero",
        ));
    }
    if total_timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "total_timeout must be greater than zero",
        ));
    }
    if connect_timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(invalid_timeout_config(
            request_timeout,
            total_timeout,
            connect_timeout,
            "connect_timeout must be greater than zero",
        ));
    }
    Ok(())
}

fn invalid_timeout_config(
    request_timeout: Duration,
    total_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    message: &'static str,
) -> Error {
    Error::InvalidTimeoutConfig {
        request_timeout_ms: request_timeout.as_millis(),
        total_timeout_ms: total_timeout.map(|timeout| timeout.as_millis()),
        connect_timeout_ms: connect_timeout.map(|timeout| timeout.as_millis()),
        message,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ClientControlPolicies {
    pub(crate) circuit_breaker: Option<CircuitBreakerPolicy>,
    pub(crate) adaptive_concurrency: Option<AdaptiveConcurrencyPolicy>,
    pub(crate) global_rate_limit: Option<RateLimitPolicy>,
    pub(crate) per_host_rate_limit: Option<RateLimitPolicy>,
}

impl ClientControlPolicies {
    pub(crate) fn validate(self) -> crate::Result<()> {
        if let Some(policy) = self.circuit_breaker {
            policy.validate()?;
        }
        if let Some(policy) = self.adaptive_concurrency {
            policy.validate()?;
        }
        if let Some(policy) = self.global_rate_limit {
            policy.validate()?;
        }
        if let Some(policy) = self.per_host_rate_limit {
            policy.validate()?;
        }
        Ok(())
    }
}

impl ClientProfile {
    pub(crate) fn defaults(self) -> ProfileDefaults {
        match self {
            Self::StandardSdk => ProfileDefaults {
                request_timeout: Duration::from_secs(10),
                total_timeout: None,
                retry_policy: RetryPolicy::standard(),
                max_response_body_bytes: 8 * 1024 * 1024,
                redirect_policy: RedirectPolicy::none(),
                status_policy: StatusPolicy::Error,
            },
            Self::LowLatency => ProfileDefaults {
                request_timeout: Duration::from_secs(2),
                total_timeout: Some(Duration::from_secs(5)),
                retry_policy: RetryPolicy::standard()
                    .max_attempts(2)
                    .base_backoff(Duration::from_millis(50))
                    .max_backoff(Duration::from_millis(300)),
                max_response_body_bytes: 2 * 1024 * 1024,
                redirect_policy: RedirectPolicy::none(),
                status_policy: StatusPolicy::Error,
            },
            Self::HighThroughput => ProfileDefaults {
                request_timeout: Duration::from_secs(20),
                total_timeout: Some(Duration::from_secs(60)),
                retry_policy: RetryPolicy::standard()
                    .max_attempts(4)
                    .base_backoff(Duration::from_millis(150))
                    .max_backoff(Duration::from_secs(3)),
                max_response_body_bytes: 32 * 1024 * 1024,
                redirect_policy: RedirectPolicy::limited(5),
                status_policy: StatusPolicy::Error,
            },
        }
    }
}
