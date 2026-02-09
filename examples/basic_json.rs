use std::time::Duration;

use reqx::prelude::{HttpClient, RetryPolicy};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct CreateItem<'a> {
    name: &'a str,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct EchoResponse {
    json: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-basic")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(10))
        .retry_policy(
            RetryPolicy::standard()
                .max_attempts(3)
                .base_backoff(Duration::from_millis(100))
                .max_backoff(Duration::from_millis(800)),
        )
        .try_build()?;

    let ping = client
        .get("/get")
        .query_pair("from", "reqx")
        .query_pair("lang", "zh")
        .send()
        .await?;

    println!(
        "GET /get => status={} body_bytes={}",
        ping.status(),
        ping.body().len()
    );

    let payload = CreateItem {
        name: "demo",
        enabled: true,
    };

    let echoed: EchoResponse = client
        .post("/anything")
        .idempotency_key("create-item-001")?
        .json(&payload)?
        .send_json()
        .await?;

    println!("POST /anything => echoed_json={:?}", echoed.json);
    Ok(())
}
