use std::time::Duration;

#[cfg(any(
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
use reqx::prelude::TlsBackend;
use reqx::prelude::{Client, TlsRootStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Replace with your real certificate paths.
    let ca_pem = std::fs::read("certs/ca.pem")?;
    let client_cert_chain_pem = std::fs::read("certs/client-cert-chain.pem")?;
    let client_key_pem = std::fs::read("certs/client-key.pem")?;

    let mut builder = Client::builder("https://minio.internal.example.com")
        .client_name("reqx-example-custom-ca-mtls")
        .request_timeout(Duration::from_secs(5))
        .tls_root_store(TlsRootStore::Specific)
        .tls_root_ca_pem(ca_pem)
        .tls_client_identity_pem(client_cert_chain_pem, client_key_pem);

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

    let client = builder.build()?;

    println!("selected tls backend = {:?}", client.tls_backend());

    // If you use native-tls and PKCS#12 identity:
    //
    // let identity_p12 = std::fs::read("certs/client-identity.p12")?;
    // let client = Client::builder("https://minio.internal.example.com")
    //     .tls_backend(TlsBackend::NativeTls)
    //     .tls_root_store(TlsRootStore::Specific)
    //     .tls_root_ca_pem(std::fs::read("certs/ca.pem")?)
    //     .tls_client_identity_pkcs12(identity_p12, "changeit")
    //     .build()?;

    Ok(())
}
