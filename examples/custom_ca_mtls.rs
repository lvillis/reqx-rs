use std::time::Duration;

use reqx::prelude::{HttpClient, TlsBackend, TlsRootStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Replace with your real certificate paths.
    let ca_pem = std::fs::read("certs/ca.pem")?;
    let client_cert_chain_pem = std::fs::read("certs/client-cert-chain.pem")?;
    let client_key_pem = std::fs::read("certs/client-key.pem")?;

    let client = HttpClient::builder("https://minio.internal.example.com")
        .client_name("reqx-example-custom-ca-mtls")
        .request_timeout(Duration::from_secs(5))
        .tls_backend(TlsBackend::RustlsRing)
        .tls_root_store(TlsRootStore::Specific)
        .tls_root_ca_pem(ca_pem)
        .tls_client_identity_pem(client_cert_chain_pem, client_key_pem)
        .try_build()?;

    println!("selected tls backend = {:?}", client.tls_backend());

    // If you use native-tls and PKCS#12 identity:
    //
    // let identity_p12 = std::fs::read("certs/client-identity.p12")?;
    // let client = HttpClient::builder("https://minio.internal.example.com")
    //     .tls_backend(TlsBackend::NativeTls)
    //     .tls_root_ca_pem(std::fs::read("certs/ca.pem")?)
    //     .tls_client_identity_pkcs12(identity_p12, "changeit")
    //     .try_build()?;

    Ok(())
}
