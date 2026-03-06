use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use reqx::advanced::Clock;
use reqx::prelude::{Client, RetryPolicy};

struct StepClock {
    system_origin: SystemTime,
    instant_origin: Instant,
    offset_ms: AtomicU64,
}

impl StepClock {
    fn new() -> Self {
        Self {
            system_origin: SystemTime::now(),
            instant_origin: Instant::now(),
            offset_ms: AtomicU64::new(0),
        }
    }

    fn advance(&self, delta: Duration) {
        let delta_ms = delta.as_millis().min(u128::from(u64::MAX)) as u64;
        self.offset_ms.fetch_add(delta_ms, Ordering::Relaxed);
    }

    fn offset(&self) -> Duration {
        Duration::from_millis(self.offset_ms.load(Ordering::Relaxed))
    }
}

impl Clock for StepClock {
    fn now_system(&self) -> SystemTime {
        self.system_origin + self.offset()
    }

    fn now_monotonic(&self) -> Instant {
        self.instant_origin + self.offset()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let control_clock = Arc::new(StepClock::new());

    let client = Client::builder("https://postman-echo.com")
        .client_name("reqx-example-advanced-time")
        .request_timeout(Duration::from_secs(2))
        .total_timeout(Duration::from_secs(6))
        .stream_deadline_slack(Duration::from_millis(25))
        .control_clock_arc(control_clock.clone())
        .retry_policy(RetryPolicy::disabled())
        .build()?;

    // Advancing the control clock is useful for deterministic Retry-After,
    // limiter, and resilience tests. Transport I/O timers still use real time.
    control_clock.advance(Duration::from_secs(30));

    let response = client.get("/get").send().await?;
    println!(
        "status={} control_clock_offset_ms={} stream_deadline_slack_ms=25",
        response.status(),
        control_clock.offset().as_millis()
    );
    Ok(())
}
