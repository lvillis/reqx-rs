use std::time::{Duration, Instant, SystemTime};

use reqx::advanced::Clock;
use reqx::prelude::{Client, RetryPolicy};

struct PassthroughClock;

impl Clock for PassthroughClock {
    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }

    fn now_monotonic(&self) -> Instant {
        Instant::now()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://postman-echo.com")
        .client_name("reqx-example-advanced-time")
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(6))
        .stream_deadline_slack(Duration::from_millis(25))
        .control_clock(PassthroughClock)
        .retry_policy(RetryPolicy::disabled())
        .build()?;

    // Keep custom control clocks aligned with wall time in live clients.
    // Reserve manual jumps for tests of Retry-After or control-loop behavior.

    let response = client.get("/get").send().await?;
    println!("status={} stream_deadline_slack_ms=25", response.status());
    Ok(())
}
