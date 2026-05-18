use std::time::Duration;

use http::header::USER_AGENT;
use http::{HeaderMap, HeaderValue};

use crate::error::Error;
use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::rate_limit::RateLimitPolicy;
use crate::resilience::{AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy};
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

#[derive(Clone, Copy, Debug)]
pub(crate) struct ClientNameConfig<'a> {
    pub(crate) client_name: &'a str,
}

impl ClientNameConfig<'_> {
    pub(crate) fn apply_to_default_headers(
        self,
        mut default_headers: HeaderMap,
    ) -> crate::Result<HeaderMap> {
        let client_user_agent = self.validate()?;
        if !default_headers.contains_key(USER_AGENT) {
            default_headers.insert(USER_AGENT, client_user_agent);
        }
        Ok(default_headers)
    }

    pub(crate) fn validate(self) -> crate::Result<HeaderValue> {
        if self.client_name.trim().is_empty() {
            return Err(self.invalid_config("client_name must not be empty"));
        }

        HeaderValue::from_str(self.client_name)
            .map_err(|_| self.invalid_config("client_name must be a valid HTTP header value"))
    }

    fn invalid_config(self, message: &'static str) -> Error {
        Error::InvalidClientNameConfig {
            client_name_len: self.client_name.len(),
            message,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ClientConcurrencyLimits {
    pub(crate) max_in_flight: Option<usize>,
    pub(crate) max_in_flight_per_host: Option<usize>,
}

impl ClientConcurrencyLimits {
    pub(crate) fn validate(self) -> crate::Result<()> {
        if self.max_in_flight == Some(0) {
            return Err(self.invalid_config("max_in_flight must be greater than zero"));
        }
        if self.max_in_flight_per_host == Some(0) {
            return Err(self.invalid_config("max_in_flight_per_host must be greater than zero"));
        }
        Ok(())
    }

    fn invalid_config(self, message: &'static str) -> Error {
        Error::InvalidConcurrencyLimitConfig {
            max_in_flight: self.max_in_flight,
            max_in_flight_per_host: self.max_in_flight_per_host,
            message,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ClientControlPolicies {
    pub(crate) retry_budget: Option<RetryBudgetPolicy>,
    pub(crate) circuit_breaker: Option<CircuitBreakerPolicy>,
    pub(crate) adaptive_concurrency: Option<AdaptiveConcurrencyPolicy>,
    pub(crate) global_rate_limit: Option<RateLimitPolicy>,
    pub(crate) per_host_rate_limit: Option<RateLimitPolicy>,
}

impl ClientControlPolicies {
    pub(crate) fn validate(self) -> crate::Result<()> {
        if let Some(policy) = self.retry_budget {
            policy.validate()?;
        }
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

pub(crate) struct ClientCommonBuildConfig<'a> {
    pub(crate) invalid_no_proxy_rule: Option<&'a str>,
    pub(crate) timeout_config: ClientTimeoutConfig,
    pub(crate) concurrency_limits: ClientConcurrencyLimits,
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) control_policies: ClientControlPolicies,
    pub(crate) client_name: &'a str,
    pub(crate) default_headers: HeaderMap,
}

impl ClientCommonBuildConfig<'_> {
    pub(crate) fn validate(self) -> crate::Result<HeaderMap> {
        if let Some(rule) = self.invalid_no_proxy_rule {
            return Err(Error::InvalidNoProxyRule {
                rule: rule.to_owned(),
            });
        }
        self.timeout_config.validate()?;
        self.concurrency_limits.validate()?;
        self.retry_policy.validate()?;
        self.control_policies.validate()?;
        ClientNameConfig {
            client_name: self.client_name,
        }
        .apply_to_default_headers(self.default_headers)
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http::header::USER_AGENT;
    use http::{HeaderMap, HeaderValue};

    use super::{
        ClientCommonBuildConfig, ClientConcurrencyLimits, ClientControlPolicies,
        ClientTimeoutConfig,
    };
    use crate::error::Error;
    use crate::retry::RetryPolicy;

    fn valid_common_build_config<'a>(
        retry_policy: &'a RetryPolicy,
        default_headers: HeaderMap,
    ) -> ClientCommonBuildConfig<'a> {
        ClientCommonBuildConfig {
            invalid_no_proxy_rule: None,
            timeout_config: ClientTimeoutConfig {
                request_timeout: Duration::from_secs(1),
                total_timeout: None,
                connect_timeout: Duration::from_secs(1),
            },
            concurrency_limits: ClientConcurrencyLimits::default(),
            retry_policy,
            control_policies: ClientControlPolicies::default(),
            client_name: "reqx-test",
            default_headers,
        }
    }

    #[test]
    fn common_build_config_injects_user_agent_when_absent() {
        let retry_policy = RetryPolicy::disabled();
        let headers = valid_common_build_config(&retry_policy, HeaderMap::new())
            .validate()
            .expect("common config should validate");

        assert_eq!(
            headers.get(USER_AGENT),
            Some(&HeaderValue::from_static("reqx-test"))
        );
    }

    #[test]
    fn common_build_config_preserves_explicit_user_agent() {
        let retry_policy = RetryPolicy::disabled();
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static("custom-sdk"));

        let headers = valid_common_build_config(&retry_policy, default_headers)
            .validate()
            .expect("common config should validate");

        assert_eq!(
            headers.get(USER_AGENT),
            Some(&HeaderValue::from_static("custom-sdk"))
        );
    }

    #[test]
    fn common_build_config_rejects_recorded_invalid_no_proxy_rule() {
        let retry_policy = RetryPolicy::disabled();
        let mut config = valid_common_build_config(&retry_policy, HeaderMap::new());
        config.invalid_no_proxy_rule = Some("https://example.com/path");

        match config
            .validate()
            .expect_err("invalid no_proxy rule should fail")
        {
            Error::InvalidNoProxyRule { rule } => {
                assert_eq!(rule, "https://example.com/path");
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
