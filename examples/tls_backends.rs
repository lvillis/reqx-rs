use std::time::Duration;

use reqx::prelude::{HttpClient, TlsBackend};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = HttpClient::builder("https://postman-echo.com")
        .client_name("reqx-example-tls")
        .request_timeout(Duration::from_secs(3));

    #[cfg(feature = "async-tls-native")]
    {
        builder = builder.tls_backend(TlsBackend::NativeTls);
    }

    #[cfg(all(
        not(feature = "async-tls-native"),
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
    {
        builder = builder.tls_backend(TlsBackend::RustlsAwsLcRs);
    }

    #[cfg(all(
        not(feature = "async-tls-native"),
        not(feature = "async-tls-rustls-aws-lc-rs"),
        feature = "async-tls-rustls-ring"
    ))]
    {
        builder = builder.tls_backend(TlsBackend::RustlsRing);
    }

    let client = builder.try_build()?;
    println!("selected tls backend = {:?}", client.tls_backend());

    let response = client.get("/status/200").send().await?;
    println!("GET /status/200 => status={}", response.status());

    Ok(())
}
