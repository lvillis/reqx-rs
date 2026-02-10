use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use reqx::prelude::{HttpClient, RetryClassifier, RetryDecision, RetryPolicy};

struct RetryOn429Only;

impl RetryClassifier for RetryOn429Only {
    fn should_retry(&self, decision: &RetryDecision) -> bool {
        decision.status == Some(StatusCode::TOO_MANY_REQUESTS)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let retry_policy = RetryPolicy::standard()
        .max_attempts(3)
        .base_backoff(Duration::from_millis(50))
        .max_backoff(Duration::from_millis(200))
        .jitter_ratio(0.0)
        .retry_classifier(Arc::new(RetryOn429Only));

    let client = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-retry-classifier")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(retry_policy)
        .build()?;

    let result = client
        .get("/status/429")
        .send()
        .await
        .map(|response| response.status().as_u16());

    match result {
        Ok(status) => {
            println!("unexpected success: status={status}");
        }
        Err(error) => {
            println!("request failed after classifier-based retries: {error}");
        }
    }

    Ok(())
}
