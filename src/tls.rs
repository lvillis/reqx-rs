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
    /// This is unsupported by the async `native-tls` backend.
    WebPki,
    /// Use the operating system trust store.
    System,
    /// Use only certificates explicitly supplied with `tls_root_ca_*`.
    Specific,
}

#[derive(Clone, Debug)]
pub(crate) enum TlsRootCertificate {
    Pem(Vec<u8>),
    Der(Vec<u8>),
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug, Default)]
pub(crate) struct TlsOptions {
    pub(crate) root_store: TlsRootStore,
    pub(crate) root_certificates: Vec<TlsRootCertificate>,
    pub(crate) client_identity: Option<TlsClientIdentity>,
    pub(crate) min_protocol_version: Option<TlsVersion>,
    pub(crate) max_protocol_version: Option<TlsVersion>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TlsVersionBounds {
    pub(crate) min: Option<TlsVersion>,
    pub(crate) max: Option<TlsVersion>,
}

impl TlsVersionBounds {
    #[cfg(any(
        feature = "async-tls-rustls-ring",
        feature = "async-tls-rustls-aws-lc-rs"
    ))]
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

pub(crate) fn tls_config_error(backend: TlsBackend, message: impl Into<String>) -> Error {
    Error::TlsConfig {
        backend: backend.as_str(),
        message: message.into(),
    }
}
