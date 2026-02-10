use std::time::Duration;

use reqx::prelude::{HttpClient, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-metrics")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .metrics_enabled(true)
        .try_build()?;

    let _ = client.get("/status/200").send().await;
    let _ = client.get("/status/503").send().await;

    let metrics = client.metrics_snapshot();
    println!(
        "started={} succeeded={} failed={} retries={}",
        metrics.requests_started,
        metrics.requests_succeeded,
        metrics.requests_failed,
        metrics.retries
    );
    println!(
        "timeout_transport={} timeout_response_body={} in_flight={} avg_latency_ms={:.2}",
        metrics.timeout_transport,
        metrics.timeout_response_body,
        metrics.in_flight,
        metrics.latency_avg_ms
    );
    println!("status_counts={:?}", metrics.status_counts);
    println!("error_counts={:?}", metrics.error_counts);

    Ok(())
}
