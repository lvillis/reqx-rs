use std::time::Duration;

use reqx::prelude::{
    AdaptiveConcurrencyPolicy, CircuitBreakerPolicy, HttpClient, RetryBudgetPolicy, RetryPolicy,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://api.example.com")
        .client_name("resilience-demo")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(10))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(5)
                .base_backoff(Duration::from_millis(100))
                .max_backoff(Duration::from_millis(800))
                .jitter_ratio(0.1),
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
        .adaptive_concurrency(
            AdaptiveConcurrencyPolicy::standard()
                .min_limit(2)
                .initial_limit(8)
                .max_limit(64)
                .increase_step(1)
                .decrease_ratio(0.8)
                .high_latency_threshold(Duration::from_millis(250)),
        )
        .build();

    let response = client.get("/v1/health").send().await?;
    println!("status={}", response.status());
    Ok(())
}
