use std::time::Duration;

use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::retry::RetryPolicy;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientProfile {
    #[default]
    StandardSdk,
    LowLatency,
    HighThroughput,
}

#[derive(Clone, Debug)]
pub struct ProfileDefaults {
    pub request_timeout: Duration,
    pub total_timeout: Option<Duration>,
    pub retry_policy: RetryPolicy,
    pub max_response_body_bytes: usize,
    pub redirect_policy: RedirectPolicy,
    pub status_policy: StatusPolicy,
}

impl ClientProfile {
    pub fn defaults(self) -> ProfileDefaults {
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

#[derive(Clone, Debug, Default)]
pub struct AdvancedConfig {
    pub request_timeout: Option<Duration>,
    pub total_timeout: Option<Duration>,
    pub max_response_body_bytes: Option<usize>,
    pub connect_timeout: Option<Duration>,
    pub redirect_policy: Option<RedirectPolicy>,
    pub default_status_policy: Option<StatusPolicy>,
}

impl AdvancedConfig {
    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = Some(request_timeout);
        self
    }

    pub fn with_total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout);
        self
    }

    pub fn with_max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = Some(max_response_body_bytes);
        self
    }

    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    pub fn with_redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = Some(redirect_policy);
        self
    }

    pub fn with_default_status_policy(mut self, default_status_policy: StatusPolicy) -> Self {
        self.default_status_policy = Some(default_status_policy);
        self
    }
}
