use std::time::Duration;

use bytes::Bytes;
use futures_util::stream;
use http_body_util::BodyExt;
use reqx::prelude::{Client, RetryPolicy};
use tokio::io::{AsyncWriteExt, sink};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder("https://postman-echo.com")
        .client_name("reqx-example-stream")
        .request_timeout(Duration::from_secs(5))
        .retry_policy(RetryPolicy::standard().max_attempts(2))
        .build()?;

    let upload_stream = stream::iter(vec![
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"hello ")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"from ")),
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"reqx")),
    ]);

    let upload_response = client
        .post("/post")
        .idempotency_key("stream-upload-001")?
        .body_stream(upload_stream)
        .send_stream()
        .await?;

    let upload_bytes = upload_response.into_body().collect().await?.to_bytes();
    println!("stream upload response bytes={}", upload_bytes.len());

    let (mut writer, reader) = tokio::io::duplex(64);
    tokio::spawn(async move {
        let _ = writer.write_all(b"reader upload payload").await;
        let _ = writer.shutdown().await;
    });
    let upload_reader_response = client
        .post("/post")
        .idempotency_key("stream-upload-reader-001")?
        .upload_from_reader(reader)
        .send_stream()
        .await?;
    println!(
        "reader upload status={}",
        upload_reader_response.status().as_u16()
    );

    let download_response = client.get("/stream/5").send_stream().await?;
    let download_bytes = download_response.into_body().collect().await?.to_bytes();
    println!("stream download bytes={}", download_bytes.len());

    let mut writer = sink();
    let copied = client
        .get("/stream/5")
        .download_to_writer_limited(&mut writer, 1024 * 1024)
        .await?;
    println!("stream copied to writer bytes={copied}");

    Ok(())
}
