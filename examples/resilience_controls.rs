use std::time::Duration;

use reqx::prelude::{Client, RetryPolicy};
use reqx::{
    AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, RetryBudgetPolicy, TimeoutPhase,
    TransportErrorKind,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.example.com")
        .client_name("resilience-demo")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(10))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(5)
                .base_backoff(Duration::from_millis(100))
                .max_backoff(Duration::from_millis(800))
                .jitter_ratio(0.1)
                .retryable_transport_error_kinds([
                    TransportErrorKind::Connect,
                    TransportErrorKind::Read,
                    TransportErrorKind::Dns,
                ])
                .retryable_timeout_phases([TimeoutPhase::Transport, TimeoutPhase::ResponseBody])
                .status_retry_window(429, 5)
                .status_retry_window(503, 4)
                .timeout_retry_window(TimeoutPhase::ResponseBody, 2)
                .transport_retry_window(TransportErrorKind::Dns, 2)
                .response_body_read_retry_window(2),
        )
        .retry_budget_policy(
            RetryBudgetPolicy::standard()
                .window(Duration::from_secs(10))
                .retry_ratio(0.2)
                .min_retries_per_window(2),
        )
        .circuit_breaker_policy(
            CircuitBreakerPolicy::standard()
                .failure_threshold(5)
                .open_timeout(Duration::from_secs(10))
                .half_open_max_requests(2)
                .half_open_success_threshold(2),
        )
        .adaptive_concurrency_policy(
            AdaptiveConcurrencyPolicy::standard()
                .min_limit(2)
                .initial_limit(8)
                .max_limit(64)
                .increase_step(1)
                .decrease_ratio(0.8)
                .high_latency_threshold(Duration::from_millis(250)),
        )
        .build()?;

    let response = client.get("/v1/health").send().await?;
    println!("status={}", response.status());
    Ok(())
}
