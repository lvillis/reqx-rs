use std::time::Duration;

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Cursor;

    use reqx::blocking::Client;
    use reqx::prelude::RetryPolicy;

    let client = Client::builder("https://postman-echo.com")
        .client_name("reqx-example-blocking-stream")
        .request_timeout(Duration::from_secs(5))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .build()?;

    let mut writer = Vec::new();
    let copied = client
        .get("/stream/5")
        .download_to_writer_limited(&mut writer, 1024 * 1024)?;
    println!("download copied bytes={copied}");

    let reader_payload = Cursor::new(b"hello from blocking reader".to_vec());
    let upload_status = client
        .post("/post")
        .idempotency_key("blocking-upload-reader-001")?
        .upload_from_reader_with_length(reader_payload, 26)?
        .send()?
        .status();
    println!("upload status={upload_status}");

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
