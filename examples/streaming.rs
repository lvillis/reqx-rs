use std::time::Duration;

use bytes::Bytes;
use futures_util::stream;
use http_body_util::BodyExt;
use reqx::prelude::{HttpClient, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-stream")
        .request_timeout(Duration::from_secs(5))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .try_build()?;

    let upload_stream = stream::iter(vec![
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"hello ")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"from ")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"reqx")),
    ]);

    let upload_response = client
        .post("/anything")
        .idempotency_key("stream-upload-001")?
        .body_stream(upload_stream)
        .send_stream()
        .await?;

    let upload_bytes = upload_response.into_body().collect().await?.to_bytes();
    println!("stream upload response bytes={}", upload_bytes.len());

    let download_response = client.get("/stream/5").send_stream().await?;
    let download_bytes = download_response.into_body().collect().await?.to_bytes();
    println!("stream download bytes={}", download_bytes.len());

    Ok(())
}
