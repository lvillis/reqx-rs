use std::time::Duration;

use reqx::prelude::Client;
use reqx::{AdvancedConfig, ClientProfile, Observer, RequestContext, RetryDecision, StatusPolicy};

#[derive(Default)]
struct ConsoleObserver;

impl Observer for ConsoleObserver {
    fn on_request_start(&self, context: &RequestContext) {
        println!(
            "start method={} uri={} attempt={}/{}",
            context.method(),
            context.uri(),
            context.attempt(),
            context.max_attempts()
        );
    }

    fn on_retry_scheduled(
        &self,
        context: &RequestContext,
        _decision: &RetryDecision,
        delay: Duration,
    ) {
        println!(
            "retry method={} uri={} after={}ms",
            context.method(),
            context.uri(),
            delay.as_millis()
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let advanced = AdvancedConfig::default()
        .with_request_timeout(Duration::from_secs(3))
        .with_total_timeout(Duration::from_secs(8))
        .with_default_status_policy(StatusPolicy::Response);

    let client = Client::builder("https://postman-echo.com")
        .profile(ClientProfile::StandardSdk)
        .advanced(advanced)
        .observer(ConsoleObserver)
        .build()?;

    let response = client.get("/status/404").send().await?;
    println!("status={}", response.status());
    Ok(())
}
