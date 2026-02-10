use std::io::Read;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, Method, Uri};

use crate::ReqxResult;
use crate::error::{HttpClientError, TransportErrorKind};
use crate::proxy::ProxyConfig;
use crate::tls::{
    TlsBackend, TlsClientIdentity, TlsOptions, TlsRootCertificate, TlsRootStore, tls_config_error,
};

#[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
use std::sync::Arc;

pub(super) const fn default_tls_backend() -> TlsBackend {
    #[cfg(feature = "blocking-tls-rustls-ring")]
    {
        return TlsBackend::RustlsRing;
    }
    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        feature = "blocking-tls-rustls-aws-lc-rs"
    ))]
    {
        return TlsBackend::RustlsAwsLcRs;
    }
    #[cfg(all(
        not(feature = "blocking-tls-rustls-ring"),
        not(feature = "blocking-tls-rustls-aws-lc-rs"),
        feature = "blocking-tls-native"
    ))]
    {
        return TlsBackend::NativeTls;
    }
    #[allow(unreachable_code)]
    TlsBackend::RustlsRing
}

pub(super) fn backend_is_available(backend: TlsBackend) -> bool {
    match backend {
        TlsBackend::RustlsRing => cfg!(feature = "blocking-tls-rustls-ring"),
        TlsBackend::RustlsAwsLcRs => cfg!(feature = "blocking-tls-rustls-aws-lc-rs"),
        TlsBackend::NativeTls => cfg!(feature = "blocking-tls-native"),
    }
}

pub(super) fn remove_content_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

pub(super) fn is_proxy_bypassed(proxy: &ProxyConfig, uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    proxy.no_proxy_rules.iter().any(|rule| rule.matches(&host))
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn parse_pem_certificates(
    backend: TlsBackend,
    pem_bundle: &[u8],
    context: &str,
) -> ReqxResult<Vec<ureq::tls::Certificate<'static>>> {
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(pem_bundle) {
        match item.map_err(|source| {
            tls_config_error(backend, format!("failed to parse PEM {context}: {source}"))
        })? {
            ureq::tls::PemItem::Certificate(certificate) => certificates.push(certificate),
            ureq::tls::PemItem::PrivateKey(_) => {}
            _ => {}
        }
    }
    if certificates.is_empty() {
        return Err(tls_config_error(
            backend,
            format!("no certificate blocks found in PEM {context}"),
        ));
    }
    Ok(certificates)
}

#[cfg(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
))]
fn build_sync_tls_config(
    backend: TlsBackend,
    tls_options: &TlsOptions,
) -> ReqxResult<ureq::tls::TlsConfig> {
    let provider = match backend {
        TlsBackend::RustlsRing | TlsBackend::RustlsAwsLcRs => ureq::tls::TlsProvider::Rustls,
        TlsBackend::NativeTls => ureq::tls::TlsProvider::NativeTls,
    };

    let mut tls_config_builder = ureq::tls::TlsConfig::builder().provider(provider);

    let mut roots = Vec::new();
    for root_certificate in &tls_options.root_certificates {
        match root_certificate {
            TlsRootCertificate::Pem(pem) => {
                roots.extend(parse_pem_certificates(backend, pem, "root certificate")?);
            }
            TlsRootCertificate::Der(der) => {
                roots.push(ureq::tls::Certificate::from_der(der).to_owned());
            }
        }
    }

    if !roots.is_empty() && tls_options.root_store != TlsRootStore::Specific {
        return Err(tls_config_error(
            backend,
            "custom root CAs require tls_root_store(TlsRootStore::Specific)",
        ));
    }

    match tls_options.root_store {
        TlsRootStore::BackendDefault => {}
        TlsRootStore::WebPki => {
            tls_config_builder = tls_config_builder.root_certs(ureq::tls::RootCerts::WebPki);
        }
        TlsRootStore::System => {
            tls_config_builder =
                tls_config_builder.root_certs(ureq::tls::RootCerts::PlatformVerifier);
        }
        TlsRootStore::Specific => {
            if roots.is_empty() {
                return Err(tls_config_error(
                    backend,
                    "tls_root_store(TlsRootStore::Specific) requires at least one root CA",
                ));
            }
            tls_config_builder =
                tls_config_builder.root_certs(ureq::tls::RootCerts::new_with_certs(&roots));
        }
    }

    if let Some(identity) = &tls_options.client_identity {
        let client_cert = match identity {
            TlsClientIdentity::Pem {
                cert_chain_pem,
                private_key_pem,
            } => {
                let cert_chain =
                    parse_pem_certificates(backend, cert_chain_pem, "mTLS certificate chain")?;
                let private_key =
                    ureq::tls::PrivateKey::from_pem(private_key_pem).map_err(|source| {
                        tls_config_error(
                            backend,
                            format!("failed to parse mTLS private key PEM: {source}"),
                        )
                    })?;
                ureq::tls::ClientCert::new_with_certs(&cert_chain, private_key)
            }
            TlsClientIdentity::Pkcs12 {
                identity_der,
                password,
            } => {
                return Err(tls_config_error(
                    backend,
                    format!(
                        "PKCS#12 identity is unsupported in sync ureq transport; use PEM cert+key (pkcs12_bytes={}, password_len={})",
                        identity_der.len(),
                        password.len(),
                    ),
                ));
            }
        };
        tls_config_builder = tls_config_builder.client_cert(Some(client_cert));
    }

    #[cfg(feature = "blocking-tls-rustls-aws-lc-rs")]
    if backend == TlsBackend::RustlsAwsLcRs {
        tls_config_builder = tls_config_builder.unversioned_rustls_crypto_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ));
    }

    Ok(tls_config_builder.build())
}

#[cfg(not(any(
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native"
)))]
fn build_sync_tls_config(
    _backend: TlsBackend,
    _tls_options: &TlsOptions,
) -> ReqxResult<ureq::tls::TlsConfig> {
    unreachable!("sync client is not compiled without sync TLS features")
}

pub(super) fn make_agent(
    tls_backend: TlsBackend,
    tls_options: &TlsOptions,
    client_name: &str,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    pool_max_idle_connections: usize,
    proxy: Option<ureq::Proxy>,
) -> ReqxResult<ureq::Agent> {
    let tls_config = build_sync_tls_config(tls_backend, tls_options)?;
    let config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .user_agent(client_name)
        .max_idle_age(pool_idle_timeout)
        .max_idle_connections_per_host(pool_max_idle_per_host)
        .max_idle_connections(pool_max_idle_connections)
        .tls_config(tls_config)
        .proxy(proxy)
        .build();
    Ok(config.new_agent())
}

#[derive(Clone)]
pub(super) struct TransportAgents {
    pub(super) direct: ureq::Agent,
    pub(super) proxy: Option<ureq::Agent>,
}

pub(super) fn classify_ureq_transport_error(error: &ureq::Error) -> TransportErrorKind {
    match error {
        ureq::Error::HostNotFound => TransportErrorKind::Dns,
        ureq::Error::Tls(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs"
        ))]
        ureq::Error::Rustls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::NativeTls(_) => TransportErrorKind::Tls,
        #[cfg(feature = "blocking-tls-native")]
        ureq::Error::Der(_) => TransportErrorKind::Tls,
        #[cfg(any(
            feature = "blocking-tls-rustls-ring",
            feature = "blocking-tls-rustls-aws-lc-rs",
            feature = "blocking-tls-native"
        ))]
        ureq::Error::Pem(_) => TransportErrorKind::Tls,
        ureq::Error::ConnectProxyFailed(_) | ureq::Error::ConnectionFailed => {
            TransportErrorKind::Connect
        }
        ureq::Error::Io(source) => match source.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                TransportErrorKind::Read
            }
            std::io::ErrorKind::NotFound => TransportErrorKind::Dns,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrNotAvailable => TransportErrorKind::Connect,
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof => TransportErrorKind::Read,
            _ => TransportErrorKind::Other,
        },
        _ => TransportErrorKind::Other,
    }
}

pub(super) fn decode_content_encoding_error(
    encoding: String,
    message: String,
    method: &Method,
    uri: &str,
) -> HttpClientError {
    HttpClientError::DecodeContentEncoding {
        encoding,
        message,
        method: method.clone(),
        uri: uri.to_owned(),
    }
}

pub(super) fn wrapped_ureq_error(io_error: &std::io::Error) -> Option<&ureq::Error> {
    io_error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ureq::Error>())
}

pub(super) enum ReadBodyError {
    Read(std::io::Error),
    TooLarge { actual_bytes: usize },
}

pub(super) fn read_all_body_limited(
    response: &mut ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut reader = response.body_mut().as_reader();
    let mut collected = Vec::new();
    let mut chunk = [0_u8; 8192];
    let mut total_len = 0_usize;

    loop {
        let read = reader.read(&mut chunk).map_err(ReadBodyError::Read)?;
        if read == 0 {
            break;
        }
        total_len = total_len.saturating_add(read);
        if total_len > max_bytes {
            return Err(ReadBodyError::TooLarge {
                actual_bytes: total_len,
            });
        }
        collected.extend_from_slice(&chunk[..read]);
    }

    Ok(Bytes::from(collected))
}
