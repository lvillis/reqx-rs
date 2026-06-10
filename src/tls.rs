use std::fmt;

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// TLS backend used by the transport.
pub enum TlsBackend {
    /// `rustls` backed by the `ring` crypto provider.
    RustlsRing,
    /// `rustls` backed by the `aws-lc-rs` crypto provider.
    RustlsAwsLcRs,
    /// The platform-native TLS stack exposed by `native-tls`.
    NativeTls,
}

impl TlsBackend {
    /// Returns a stable backend identifier for logs, metrics, and errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustlsRing => "rustls-ring",
            Self::RustlsAwsLcRs => "rustls-aws-lc-rs",
            Self::NativeTls => "native-tls",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
/// Supported TLS protocol versions.
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

impl TlsVersion {
    /// Returns the wire-format display name for this TLS version.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1_2 => "TLS1.2",
            Self::V1_3 => "TLS1.3",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
/// Root certificate source used when verifying TLS peers.
pub enum TlsRootStore {
    #[default]
    /// Use the backend's default trust store behavior.
    ///
    /// For `rustls` backends this uses bundled Mozilla roots. For `native-tls`
    /// it uses the platform trust store.
    BackendDefault,
    /// Use the bundled Mozilla roots from `webpki-roots`.
    ///
    /// Rustls backends append any certificates supplied with `tls_root_ca_*`
    /// to this bundled root set. This is unsupported by `native-tls` backends.
    WebPki,
    /// Use the operating system trust store.
    System,
    /// Use only certificates explicitly supplied with `tls_root_ca_*`.
    Specific,
}

#[derive(Clone)]
pub(crate) enum TlsRootCertificate {
    Pem(Vec<u8>),
    Der(Vec<u8>),
}

impl fmt::Debug for TlsRootCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem(pem) => formatter
                .debug_struct("Pem")
                .field("pem_len", &pem.len())
                .finish(),
            Self::Der(der) => formatter
                .debug_struct("Der")
                .field("der_len", &der.len())
                .finish(),
        }
    }
}

#[derive(Clone)]
pub(crate) enum TlsClientIdentity {
    Pem {
        cert_chain_pem: Vec<u8>,
        private_key_pem: Vec<u8>,
    },
    Pkcs12 {
        identity_der: Vec<u8>,
        password: String,
    },
}

impl fmt::Debug for TlsClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem {
                cert_chain_pem,
                private_key_pem,
            } => formatter
                .debug_struct("Pem")
                .field("cert_chain_pem_len", &cert_chain_pem.len())
                .field("private_key_pem_len", &private_key_pem.len())
                .finish(),
            Self::Pkcs12 {
                identity_der,
                password,
            } => formatter
                .debug_struct("Pkcs12")
                .field("identity_der_len", &identity_der.len())
                .field("password_len", &password.len())
                .finish(),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct TlsOptions {
    pub(crate) root_store: TlsRootStore,
    pub(crate) root_certificates: Vec<TlsRootCertificate>,
    pub(crate) client_identity: Option<TlsClientIdentity>,
    pub(crate) min_protocol_version: Option<TlsVersion>,
    pub(crate) max_protocol_version: Option<TlsVersion>,
}

impl fmt::Debug for TlsOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsOptions")
            .field("root_store", &self.root_store)
            .field("root_certificates", &self.root_certificates)
            .field("client_identity", &self.client_identity)
            .field("min_protocol_version", &self.min_protocol_version)
            .field("max_protocol_version", &self.max_protocol_version)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
pub(crate) struct TlsVersionBounds {
    pub(crate) min: Option<TlsVersion>,
    pub(crate) max: Option<TlsVersion>,
}

#[cfg(any(
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs"
))]
impl TlsVersionBounds {
    pub(crate) fn contains(self, version: TlsVersion) -> bool {
        self.min.is_none_or(|min| version >= min) && self.max.is_none_or(|max| version <= max)
    }
}

#[cfg(all(feature = "_async", feature = "async-tls-native"))]
impl TlsOptions {
    pub(crate) fn has_customizations(&self) -> bool {
        self.root_store != TlsRootStore::BackendDefault
            || !self.root_certificates.is_empty()
            || self.client_identity.is_some()
            || self.min_protocol_version.is_some()
            || self.max_protocol_version.is_some()
    }
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
pub(crate) fn tls_version_bounds(
    backend: TlsBackend,
    tls_options: &TlsOptions,
) -> crate::Result<TlsVersionBounds> {
    let bounds = TlsVersionBounds {
        min: tls_options.min_protocol_version,
        max: tls_options.max_protocol_version,
    };
    if let (Some(min), Some(max)) = (bounds.min, bounds.max)
        && min > max
    {
        return Err(tls_config_error(
            backend,
            format!(
                "invalid TLS version range: min version {} is greater than max version {}",
                min.as_str(),
                max.as_str()
            ),
        ));
    }
    Ok(bounds)
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
pub(crate) fn tls_config_error(backend: TlsBackend, message: impl Into<String>) -> Error {
    Error::TlsConfig {
        backend: backend.as_str(),
        message: message.into(),
    }
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
fn contains_pem_marker(haystack: &[u8], marker: &[u8]) -> bool {
    find_subslice(haystack, marker).is_some()
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
fn is_pem_outer_padding(value: &[u8]) -> bool {
    value.iter().all(u8::is_ascii_whitespace)
}

#[cfg(any(
    test,
    feature = "async-tls-native",
    feature = "async-tls-rustls-ring",
    feature = "async-tls-rustls-aws-lc-rs",
    feature = "blocking-tls-native",
    feature = "blocking-tls-rustls-ring",
    feature = "blocking-tls-rustls-aws-lc-rs"
))]
pub(crate) fn parse_pem_certificate_blocks(
    backend: TlsBackend,
    pem_bundle: &[u8],
    context: &str,
) -> crate::Result<Vec<Vec<u8>>> {
    const PEM_BEGIN_PREFIX: &[u8] = b"-----BEGIN ";
    const PEM_END_PREFIX: &[u8] = b"-----END ";
    const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    loop {
        let remaining = &pem_bundle[cursor..];
        let next_begin = find_subslice(remaining, PEM_BEGIN_PREFIX);
        let next_end = find_subslice(remaining, PEM_END_PREFIX);

        match (next_begin, next_end) {
            (None, None) => {
                if !is_pem_outer_padding(remaining) {
                    return Err(tls_config_error(
                        backend,
                        format!("PEM {context} contains data outside certificate blocks"),
                    ));
                }
                break;
            }
            (None, Some(_)) => {
                return Err(tls_config_error(
                    backend,
                    format!("PEM {context} contains an end marker without a matching begin marker"),
                ));
            }
            (Some(begin_offset), Some(end_offset)) if end_offset < begin_offset => {
                return Err(tls_config_error(
                    backend,
                    format!("PEM {context} contains an end marker without a matching begin marker"),
                ));
            }
            (Some(begin_offset), _) => {
                let begin = cursor + begin_offset;
                if !is_pem_outer_padding(&pem_bundle[cursor..begin]) {
                    return Err(tls_config_error(
                        backend,
                        format!("PEM {context} contains data outside certificate blocks"),
                    ));
                }
                if !pem_bundle[begin..].starts_with(PEM_BEGIN) {
                    return Err(tls_config_error(
                        backend,
                        format!("PEM {context} contains a non-certificate block"),
                    ));
                }

                let end_search_start = begin + PEM_BEGIN.len();
                let Some(end_offset) = find_subslice(&pem_bundle[end_search_start..], PEM_END)
                else {
                    return Err(tls_config_error(
                        backend,
                        format!("PEM {context} block is missing its END CERTIFICATE marker"),
                    ));
                };

                if contains_pem_marker(
                    &pem_bundle[end_search_start..end_search_start + end_offset],
                    PEM_BEGIN_PREFIX,
                ) {
                    return Err(tls_config_error(
                        backend,
                        format!("PEM {context} contains a nested begin marker"),
                    ));
                }

                let end = end_search_start + end_offset + PEM_END.len();
                let mut block_end = end;
                while block_end < pem_bundle.len()
                    && (pem_bundle[block_end] == b'\n' || pem_bundle[block_end] == b'\r')
                {
                    block_end += 1;
                }
                blocks.push(pem_bundle[begin..block_end].to_vec());
                cursor = block_end;
            }
        }
    }

    if blocks.is_empty() {
        return Err(tls_config_error(
            backend,
            format!("no certificate blocks found in PEM {context}"),
        ));
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::{TlsBackend, parse_pem_certificate_blocks};
    use crate::error::Error;

    #[test]
    fn pem_certificate_parser_rejects_unterminated_certificate_tail() {
        let pem = concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "AQIDBA==\n",
            "-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\n",
            "AQIDBA==\n",
        );

        let error = parse_pem_certificate_blocks(
            TlsBackend::RustlsRing,
            pem.as_bytes(),
            "root certificate",
        )
        .expect_err("unterminated certificate block must not be silently ignored");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("missing its END CERTIFICATE marker"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn pem_certificate_parser_rejects_non_certificate_blocks() {
        let pem = concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "AQIDBA==\n",
            "-----END PRIVATE KEY-----\n",
        );

        let error = parse_pem_certificate_blocks(
            TlsBackend::RustlsRing,
            pem.as_bytes(),
            "root certificate",
        )
        .expect_err("root CA PEM must not accept non-certificate PEM blocks");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("non-certificate block"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn pem_certificate_parser_rejects_data_before_certificate_block() {
        let pem = concat!(
            "Bag Attributes\n",
            "-----BEGIN CERTIFICATE-----\n",
            "AQIDBA==\n",
            "-----END CERTIFICATE-----\n",
        );

        let error = parse_pem_certificate_blocks(
            TlsBackend::RustlsRing,
            pem.as_bytes(),
            "root certificate",
        )
        .expect_err("root CA PEM must not accept text outside certificate blocks");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("data outside certificate blocks"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn pem_certificate_parser_rejects_data_after_certificate_block() {
        let pem = concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "AQIDBA==\n",
            "-----END CERTIFICATE-----\n",
            "trailing data\n",
        );

        let error = parse_pem_certificate_blocks(
            TlsBackend::RustlsRing,
            pem.as_bytes(),
            "root certificate",
        )
        .expect_err("root CA PEM must not accept trailing text outside certificate blocks");

        match error {
            Error::TlsConfig { message, .. } => {
                assert!(message.contains("data outside certificate blocks"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
