use std::time::Duration;

use reqx::prelude::{HttpClient, RetryPolicy};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
struct SearchQuery<'a> {
    term: &'a str,
    page: u32,
}

#[derive(Debug, Serialize)]
struct LoginForm<'a> {
    username: &'a str,
    password: &'a str,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-request-helpers")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::disabled())
        .try_default_header("x-sdk-version", "1.0.0")?
        .try_build()?;

    let get_response: Value = client
        .get("/get")
        .query(&SearchQuery {
            term: "reqx",
            page: 2,
        })?
        .try_header("x-request-id", "req-001")?
        .send_json()
        .await?;
    println!("GET /get args={:?}", get_response.get("args"));

    let form_response: Value = client
        .post("/post")
        .form(&LoginForm {
            username: "alice",
            password: "secret",
        })?
        .send_json()
        .await?;
    println!("POST /post form={:?}", form_response.get("form"));

    Ok(())
}
