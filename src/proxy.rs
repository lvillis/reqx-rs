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
use hyper_util::client::legacy::connect::HttpConnector;
#[cfg(feature = "_async")]
use hyper_util::client::legacy::connect::proxy::Tunnel;
#[cfg(feature = "_async")]
use tower_service::Service;
use url::Url;

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
    Domain(String),
}

impl NoProxyRule {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut candidate = text.trim().to_owned();
        if candidate.is_empty() {
            return None;
        }
        if candidate == "*" {
            return Some(Self::Any);
        }
        if let Ok(url) = Url::parse(&candidate) {
            candidate = url.host_str().unwrap_or_default().to_owned();
        }
        candidate = candidate.trim_start_matches('.').to_owned();
        if candidate.starts_with('[')
            && let Some(end) = candidate.find(']')
        {
            candidate = candidate[1..end].to_owned();
        }
        if let Some((host, port)) = candidate.rsplit_once(':')
            && !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && !host.is_empty()
        {
            candidate = host.to_owned();
        }
        if candidate.is_empty() {
            return None;
        }
        Some(Self::Domain(candidate.to_ascii_lowercase()))
    }

    pub(crate) fn matches(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Domain(domain) => host == domain || host.ends_with(&format!(".{domain}")),
        }
    }
}

#[derive(Clone)]
#[cfg(feature = "_async")]
struct ProxyRuntime {
    tunnel: Tunnel<HttpConnector>,
    no_proxy_rules: Vec<NoProxyRule>,
}

#[cfg(feature = "_async")]
impl ProxyRuntime {
    fn should_bypass_proxy(&self, uri: &Uri) -> bool {
        let Some(host) = uri.host() else {
            return false;
        };
        let normalized = host.to_ascii_lowercase();
        self.no_proxy_rules
            .iter()
            .any(|rule| rule.matches(&normalized))
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
            let mut tunnel = Tunnel::new(config.uri, direct.clone());
            if let Some(authorization) = config.authorization {
                tunnel = tunnel.with_auth(authorization);
            }
            ProxyRuntime {
                tunnel,
                no_proxy_rules: config.no_proxy_rules,
            }
        });
        Self { direct, proxy }
    }
}

#[cfg(feature = "_async")]
impl Service<Uri> for ProxyConnector {
    type Response = <HttpConnector as Service<Uri>>::Response;
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
                return Box::pin(
                    async move { connecting.await.map_err(|error| Box::new(error) as _) },
                );
            }
            let tunnel_target = normalize_tunnel_target_uri(dst);
            let connecting = proxy.tunnel.call(tunnel_target);
            return Box::pin(async move { connecting.await.map_err(|error| Box::new(error) as _) });
        }

        let connecting = self.direct.call(dst);
        Box::pin(async move { connecting.await.map_err(|error| Box::new(error) as _) })
    }
}

#[cfg(feature = "_async")]
pub(crate) fn normalize_tunnel_target_uri(dst: Uri) -> Uri {
    if dst.port().is_some() {
        return dst;
    }

    let default_port = match dst.scheme_str() {
        Some("https") => 443,
        Some("http") => 80,
        _ => return dst,
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
