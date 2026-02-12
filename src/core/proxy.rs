#[cfg(feature = "_async")]
use std::error::Error as StdError;
#[cfg(feature = "_async")]
use std::future::Future;
#[cfg(feature = "_async")]
use std::pin::Pin;
#[cfg(feature = "_async")]
use std::task::{Context, Poll};
#[cfg(feature = "_async")]
use std::time::Duration;

use http::Uri;
use http::header::HeaderValue;
#[cfg(feature = "_async")]
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
#[cfg(feature = "_async")]
use hyper_util::client::legacy::connect::proxy::Tunnel;
#[cfg(feature = "_async")]
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
#[cfg(feature = "_async")]
use tower_service::Service;
use url::Url;

use crate::error::Error;
use crate::util::default_port;

#[cfg(feature = "_async")]
pub(crate) type BoxConnectError = Box<dyn StdError + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ProxyConfig {
    pub(crate) uri: Uri,
    pub(crate) authorization: Option<HeaderValue>,
    pub(crate) no_proxy_rules: Vec<NoProxyRule>,
}

#[derive(Clone, Debug)]
pub(crate) enum NoProxyRule {
    Any,
    Domain { host: String, port: Option<u16> },
}

impl NoProxyRule {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut candidate = text.trim().to_owned();
        let mut port = None;
        if candidate.is_empty() {
            return None;
        }
        if candidate == "*" {
            return Some(Self::Any);
        }
        if let Ok(url) = Url::parse(&candidate)
            && let Some(host) = url.host_str()
        {
            candidate = host.to_owned();
            port = url.port();
        }
        candidate = candidate.trim_start_matches('.').to_owned();
        if candidate.is_empty() {
            return None;
        }
        if let Some(stripped) = candidate.strip_prefix('[') {
            let end = stripped.find(']')?;
            let host = &stripped[..end];
            let suffix = &stripped[end + 1..];
            if suffix.is_empty() {
                port = None;
            } else if let Some(raw_port) = suffix.strip_prefix(':') {
                port = Some(raw_port.parse::<u16>().ok()?);
            } else {
                return None;
            }
            candidate = host.to_owned();
        } else if candidate.matches(':').count() == 1 {
            let (host, raw_port) = candidate.rsplit_once(':')?;
            if host.is_empty() {
                return None;
            }
            port = Some(raw_port.parse::<u16>().ok()?);
            candidate = host.to_owned();
        }
        if candidate.is_empty() {
            return None;
        }
        Some(Self::Domain {
            host: candidate.to_ascii_lowercase(),
            port,
        })
    }

    pub(crate) fn matches(&self, host: &str, port: Option<u16>) -> bool {
        match self {
            Self::Any => true,
            Self::Domain {
                host: domain,
                port: rule_port,
            } => {
                let host_matches = host == domain || host.ends_with(&format!(".{domain}"));
                if !host_matches {
                    return false;
                }

                match rule_port {
                    Some(rule_port) => port == Some(*rule_port),
                    None => true,
                }
            }
        }
    }
}

pub(crate) fn should_bypass_proxy_uri(no_proxy_rules: &[NoProxyRule], uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    let normalized = host.to_ascii_lowercase();
    let port = uri.port_u16().or_else(|| default_port(uri));
    no_proxy_rules
        .iter()
        .any(|rule| rule.matches(&normalized, port))
}

pub(crate) fn parse_no_proxy_rule(rule: &str) -> crate::Result<NoProxyRule> {
    NoProxyRule::parse(rule).ok_or_else(|| Error::InvalidNoProxyRule {
        rule: rule.to_owned(),
    })
}

pub(crate) fn parse_no_proxy_rules<I, S>(rules: I) -> crate::Result<Vec<NoProxyRule>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    rules
        .into_iter()
        .map(|rule| parse_no_proxy_rule(rule.as_ref()))
        .collect()
}

#[derive(Clone)]
#[cfg(feature = "_async")]
struct ProxyRuntime {
    tunnel: Tunnel<HttpConnector>,
    proxy_uri: Uri,
    no_proxy_rules: Vec<NoProxyRule>,
}

#[cfg(feature = "_async")]
impl ProxyRuntime {
    fn should_bypass_proxy(&self, uri: &Uri) -> bool {
        should_bypass_proxy_uri(&self.no_proxy_rules, uri)
    }
}

#[cfg(feature = "_async")]
#[derive(Debug)]
pub(crate) struct ProxyConnection<T> {
    inner: T,
    proxied: bool,
}

#[cfg(feature = "_async")]
impl<T> ProxyConnection<T> {
    fn new(inner: T, proxied: bool) -> Self {
        Self { inner, proxied }
    }
}

#[cfg(feature = "_async")]
impl<T> HyperRead for ProxyConnection<T>
where
    T: HyperRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "_async")]
impl<T> HyperWrite for ProxyConnection<T>
where
    T: HyperWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = &mut self.get_mut().inner;
        Pin::new(inner).poll_write_vectored(cx, bufs)
    }
}

#[cfg(feature = "_async")]
impl<T> Connection for ProxyConnection<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        self.inner.connected().proxy(self.proxied)
    }
}

#[derive(Clone)]
#[cfg(feature = "_async")]
pub(crate) struct ProxyConnector {
    direct: HttpConnector,
    proxy: Option<ProxyRuntime>,
}

#[cfg(feature = "_async")]
impl ProxyConnector {
    pub(crate) fn new(proxy_config: Option<ProxyConfig>, connect_timeout: Duration) -> Self {
        let mut direct = HttpConnector::new();
        direct.enforce_http(false);
        direct.set_connect_timeout(Some(connect_timeout));
        let proxy = proxy_config.map(|config| {
            let mut tunnel = Tunnel::new(config.uri.clone(), direct.clone());
            if let Some(authorization) = config.authorization {
                tunnel = tunnel.with_auth(authorization);
            }
            ProxyRuntime {
                tunnel,
                proxy_uri: config.uri,
                no_proxy_rules: config.no_proxy_rules,
            }
        });
        Self { direct, proxy }
    }
}

#[cfg(feature = "_async")]
impl Service<Uri> for ProxyConnector {
    type Response = ProxyConnection<<HttpConnector as Service<Uri>>::Response>;
    type Error = BoxConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(proxy) = &mut self.proxy {
            let direct_ready = match self.direct.poll_ready(cx) {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => false,
            };
            let tunnel_ready = match proxy.tunnel.poll_ready(cx) {
                Poll::Ready(Ok(())) => true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => false,
            };
            return if direct_ready && tunnel_ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }

        match self.direct.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        if let Some(proxy) = &mut self.proxy {
            if proxy.should_bypass_proxy(&dst) {
                let connecting = self.direct.call(dst);
                return Box::pin(async move {
                    connecting
                        .await
                        .map(|connection| ProxyConnection::new(connection, false))
                        .map_err(|error| Box::new(error) as _)
                });
            }
            let scheme = dst.scheme_str().unwrap_or_default();
            if scheme.eq_ignore_ascii_case("https") {
                let tunnel_target = normalize_tunnel_target_uri(dst);
                let connecting = proxy.tunnel.call(tunnel_target);
                return Box::pin(async move {
                    connecting
                        .await
                        .map(|connection| ProxyConnection::new(connection, false))
                        .map_err(|error| Box::new(error) as _)
                });
            }
            let connecting = self.direct.call(proxy.proxy_uri.clone());
            return Box::pin(async move {
                connecting
                    .await
                    .map(|connection| ProxyConnection::new(connection, true))
                    .map_err(|error| Box::new(error) as _)
            });
        }

        let connecting = self.direct.call(dst);
        Box::pin(async move {
            connecting
                .await
                .map(|connection| ProxyConnection::new(connection, false))
                .map_err(|error| Box::new(error) as _)
        })
    }
}

#[cfg(feature = "_async")]
pub(crate) fn normalize_tunnel_target_uri(dst: Uri) -> Uri {
    if dst.port().is_some() {
        return dst;
    }

    let Some(scheme) = dst.scheme_str() else {
        return dst;
    };
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        return dst;
    };
    let Some(host) = dst.host() else {
        return dst;
    };
    let authority_text = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{default_port}")
    } else {
        format!("{host}:{default_port}")
    };

    let Ok(authority) = authority_text.parse() else {
        return dst;
    };
    let original = dst.clone();
    let mut parts = dst.into_parts();
    parts.authority = Some(authority);
    Uri::from_parts(parts).unwrap_or(original)
}
