use std::time::Duration;

use reqx::prelude::{HttpClient, RetryPolicy};
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-concurrency")
        .request_timeout(Duration::from_secs(5))
        .retry_policy(RetryPolicy::disabled())
        .max_in_flight(1)
        .try_build()?;

    let started = Instant::now();
    let mut handles = Vec::new();

    for idx in 0..3 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let result = client.get("/delay/1").send().await;
            (idx, result.map(|response| response.status().as_u16()))
        }));
    }

    for handle in handles {
        let (idx, result) = handle.await?;
        match result {
            Ok(status) => println!("request-{idx} status={status}"),
            Err(error) => println!("request-{idx} error={error}"),
        }
    }

    println!("elapsed_ms={}", started.elapsed().as_millis());
    Ok(())
}
