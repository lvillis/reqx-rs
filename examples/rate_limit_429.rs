use std::time::Duration;

use reqx::prelude::{Client, RateLimitPolicy, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://api.example.com")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::disabled())
        .global_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(20.0)
                .burst(40)
                .max_throttle_delay(Duration::from_secs(30)),
        )
        .per_host_rate_limit_policy(
            RateLimitPolicy::standard()
                .requests_per_second(10.0)
                .burst(20),
        )
        .build()?;

    let response = client.get("/v1/resources").send().await?;
    println!("status={}", response.status());
    Ok(())
}
