use std::time::Duration;

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use reqx::blocking::HttpClient;
    use reqx::prelude::RetryPolicy;

    let client = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-blocking-stream")
        .request_timeout(Duration::from_secs(5))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .build();

    let response = client.get("/stream/5").send_stream()?;
    let status = response.status().as_u16();
    let body = response.into_text_limited(1024 * 1024)?;
    println!("status={status} chars={}", body.len());

    Ok(())
}

#[cfg(not(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
)))]
fn main() {
    let _ = Duration::from_secs(1);
    eprintln!("enable a `blocking-tls-*` feature to run this example");
}
