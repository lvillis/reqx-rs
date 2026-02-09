use std::time::Duration;

use reqx::prelude::{HttpClient, HttpClientError, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-error-handling")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::disabled())
        .try_build()?;

    let result = client.get("/status/500").send().await;
    match result {
        Ok(response) => {
            println!("unexpected success: status={}", response.status());
        }
        Err(error) => {
            println!("error_code={}", error.code().as_str());
            match &error {
                HttpClientError::HttpStatus { status, body, .. } => {
                    println!("http status error: status={status} body={body}");
                }
                HttpClientError::Timeout {
                    phase, timeout_ms, ..
                } => {
                    println!("timeout: phase={phase} timeout_ms={timeout_ms}");
                }
                HttpClientError::Transport { kind, .. } => {
                    println!("transport error kind={kind}");
                }
                other => {
                    println!("other error: {other}");
                }
            }
        }
    }

    Ok(())
}
