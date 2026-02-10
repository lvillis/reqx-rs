use std::time::Duration;

use reqx::prelude::{Error, HttpClient, RetryPolicy, TimeoutPhase};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-overrides")
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(8))
        .retry_policy(RetryPolicy::standard().max_attempts(3))
        .build()?;

    let fast = client
        .get("/delay/1")
        .timeout(Duration::from_millis(300))
        .retry_policy(RetryPolicy::disabled())
        .send()
        .await;

    match fast {
        Ok(response) => {
            println!("unexpected success: status={}", response.status());
        }
        Err(Error::Timeout { phase, .. }) if phase == TimeoutPhase::Transport => {
            println!("request-level timeout works: phase={phase}");
        }
        Err(other) => {
            println!("request failed with: {other}");
        }
    }

    let stable = client
        .get("/get")
        .timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .send()
        .await?;

    println!("GET /get => status={}", stable.status());
    Ok(())
}
