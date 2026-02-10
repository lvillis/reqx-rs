use std::time::Duration;

use reqx::prelude::{Error, HttpClient, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-error-handling")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::disabled())
        .build()?;

    let result = client.get("/status/500").send().await;
    match result {
        Ok(response) => {
            println!("unexpected success: status={}", response.status());
        }
        Err(error) => {
            println!("error_code={}", error.code().as_str());
            match &error {
                Error::HttpStatus { status, body, .. } => {
                    println!("http status error: status={status} body={body}");
                }
                Error::Timeout {
                    phase, timeout_ms, ..
                } => {
                    println!("timeout: phase={phase} timeout_ms={timeout_ms}");
                }
                Error::Transport { kind, .. } => {
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
