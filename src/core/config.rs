use std::time::Duration;

use crate::policy::{RedirectPolicy, StatusPolicy};
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
