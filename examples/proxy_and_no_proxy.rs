use std::time::Duration;

use http::Uri;
use reqx::prelude::{HttpClient, RetryPolicy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_uri: Uri = "http://proxy.example.com:8080".parse()?;

    let client = HttpClient::builder("https://httpbin.org")
        .client_name("reqx-example-proxy")
        .request_timeout(Duration::from_secs(3))
        .retry_policy(RetryPolicy::disabled())
        .http_proxy(proxy_uri)
        .try_proxy_authorization("Basic ZGVtbzpkZW1v")?
        .no_proxy(["localhost", "127.0.0.1", ".internal.example.com"])
        .try_build()?;

    // This example focuses on proxy configuration. Update the proxy URI above and
    // issue a real request in your environment if needed.
    println!(
        "proxy-configured client built successfully, tls_backend={:?}",
        client.tls_backend()
    );

    Ok(())
}
