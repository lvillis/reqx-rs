use std::time::Duration;

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use reqx::blocking::HttpClient;

    let client = HttpClient::builder("https://api.example.com")
        .client_name("example-sdk")
        .request_timeout(Duration::from_secs(3))
        .total_timeout(Duration::from_secs(8))
        .build()?;

    let response = client.get("/v1/items").send()?;
    println!("status={}", response.status());
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
