use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsBackend {
    RustlsRing,
    RustlsAwsLcRs,
    NativeTls,
}

impl TlsBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RustlsRing => "rustls-ring",
            Self::RustlsAwsLcRs => "rustls-aws-lc-rs",
            Self::NativeTls => "native-tls",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TlsRootStore {
    #[default]
    BackendDefault,
    WebPki,
    System,
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
}

#[cfg(all(feature = "_async", feature = "async-tls-native"))]
impl TlsOptions {
    pub(crate) fn has_customizations(&self) -> bool {
        self.root_store != TlsRootStore::BackendDefault
            || !self.root_certificates.is_empty()
            || self.client_identity.is_some()
    }
}

pub(crate) fn tls_config_error(backend: TlsBackend, message: impl Into<String>) -> Error {
    Error::TlsConfig {
        backend: backend.as_str(),
        message: message.into(),
    }
}
