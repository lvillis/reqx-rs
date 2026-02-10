use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderName, HeaderValue,
    LOCATION, RETRY_AFTER,
};
use http::{HeaderMap, Method, StatusCode, Uri};

use crate::error::Error;
#[cfg(feature = "_async")]
use crate::error::TransportErrorKind;

const MAX_ERROR_BODY_LEN: usize = 2048;

pub(crate) fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn merge_headers(default_headers: &HeaderMap, request_headers: &HeaderMap) -> HeaderMap {
    let mut merged = default_headers.clone();
    for (name, value) in request_headers {
        merged.insert(name.clone(), value.clone());
    }
    merged
}

fn ensure_accept_encoding(headers: &mut HeaderMap, value: &'static str) {
    if !headers.contains_key(ACCEPT_ENCODING) {
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
    }
}

#[cfg(feature = "_async")]
pub(crate) fn ensure_accept_encoding_async(headers: &mut HeaderMap) {
    ensure_accept_encoding(headers, "gzip, br, deflate, zstd");
}

#[cfg(feature = "_blocking")]
pub(crate) fn ensure_accept_encoding_blocking(headers: &mut HeaderMap) {
    ensure_accept_encoding(headers, "gzip, br");
}

fn invalid_base_url_error(base_url: &str) -> Error {
    Error::InvalidUri {
        uri: base_url.to_owned(),
    }
}

pub(crate) fn redact_uri_for_logs(uri_text: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(uri_text) else {
        return uri_text.split('?').next().unwrap_or(uri_text).to_owned();
    };

    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);

    let mut path_segments = parsed
        .path_segments()
        .map(|segments| segments.map(ToOwned::to_owned).collect::<Vec<_>>())
        .unwrap_or_default();
    if !path_segments.is_empty() {
        for segment in &mut path_segments {
            if let Some(rest) = segment.strip_prefix("bot")
                && !rest.is_empty()
                && rest.contains(':')
            {
                *segment = "bot<redacted>".to_owned();
            }
        }

        let has_trailing_slash = parsed.path().ends_with('/');
        let mut rebuilt_path = String::new();
        for segment in &path_segments {
            rebuilt_path.push('/');
            rebuilt_path.push_str(segment);
        }
        if rebuilt_path.is_empty() || (has_trailing_slash && !rebuilt_path.ends_with('/')) {
            rebuilt_path.push('/');
        }
        parsed.set_path(&rebuilt_path);
    }

    parsed.to_string()
}

pub(crate) fn resolve_uri(base_url: &str, path: &str) -> Result<(String, Uri), Error> {
    let uri_text = match path.parse::<Uri>() {
        Ok(uri) if uri.host().is_some() => {
            let Some(scheme) = uri.scheme_str() else {
                return Err(Error::InvalidUri {
                    uri: path.to_owned(),
                });
            };
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
                path.to_owned()
            } else {
                return Err(Error::InvalidUri {
                    uri: path.to_owned(),
                });
            }
        }
        _ => join_base_path(base_url, path),
    };
    let uri = uri_text.parse().map_err(|_| Error::InvalidUri {
        uri: uri_text.clone(),
    })?;
    Ok((uri_text, uri))
}

pub(crate) fn validate_base_url(base_url: &str) -> Result<(), Error> {
    let normalized = base_url.trim();
    if normalized.len() != base_url.len() {
        return Err(invalid_base_url_error(base_url));
    }
    if normalized.is_empty() {
        return Err(invalid_base_url_error(base_url));
    }

    let parsed = url::Url::parse(normalized).map_err(|_| invalid_base_url_error(base_url))?;
    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https") {
        return Err(invalid_base_url_error(base_url));
    }
    if parsed.host_str().is_none() {
        return Err(invalid_base_url_error(base_url));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_base_url_error(base_url));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_base_url_error(base_url));
    }

    let uri = normalized
        .parse::<Uri>()
        .map_err(|_| invalid_base_url_error(base_url))?;
    if uri.scheme_str().is_none() || uri.host().is_none() {
        return Err(invalid_base_url_error(base_url));
    };

    Ok(())
}

pub(crate) fn append_query_pairs(path: &str, query_pairs: &[(String, String)]) -> String {
    if query_pairs.is_empty() {
        return path.to_owned();
    }

    if let Ok(mut url) = url::Url::parse(path) {
        let existing = url
            .query()
            .map(|query| {
                url::form_urlencoded::parse(query.as_bytes())
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let query = build_query_string(&existing, query_pairs);
        url.set_query(Some(&query));
        return url.to_string();
    }

    let (without_fragment, fragment) = match path.split_once('#') {
        Some((left, right)) => (left, Some(right)),
        None => (path, None),
    };
    let (base, existing_query) = match without_fragment.split_once('?') {
        Some((left, right)) => (left, Some(right)),
        None => (without_fragment, None),
    };
    let existing = existing_query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let query = build_query_string(&existing, query_pairs);

    let mut merged = format!("{base}?{query}");
    if let Some(fragment) = fragment {
        merged.push('#');
        merged.push_str(fragment);
    }
    merged
}

fn build_query_string(existing: &[(String, String)], appended: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in existing {
        serializer.append_pair(name, value);
    }
    for (name, value) in appended {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

#[cfg(feature = "_async")]
pub(crate) fn classify_transport_error(
    error: &hyper_util::client::legacy::Error,
) -> TransportErrorKind {
    if error.is_connect() {
        let text = error.to_string().to_ascii_lowercase();
        if text.contains("dns")
            || text.contains("name or service not known")
            || text.contains("failed to lookup address")
        {
            return TransportErrorKind::Dns;
        }
        if text.contains("tls") || text.contains("certificate") || text.contains("handshake") {
            return TransportErrorKind::Tls;
        }
        return TransportErrorKind::Connect;
    }

    let text = error.to_string().to_ascii_lowercase();
    if text.contains("read")
        || text.contains("connection reset")
        || text.contains("broken pipe")
        || text.contains("unexpected eof")
    {
        return TransportErrorKind::Read;
    }

    TransportErrorKind::Other
}

pub(crate) fn join_base_path(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let relative = path.trim_start_matches('/');
    match (base.is_empty(), relative.is_empty()) {
        (true, true) => String::new(),
        (true, false) => relative.to_owned(),
        (false, true) => base.to_owned(),
        (false, false) => format!("{base}/{relative}"),
    }
}

pub(crate) fn parse_header_name(name: &str) -> Result<HeaderName, Error> {
    name.parse().map_err(|source| Error::InvalidHeaderName {
        name: name.to_owned(),
        source,
    })
}

pub(crate) fn parse_header_value(name: &str, value: &str) -> Result<HeaderValue, Error> {
    value.parse().map_err(|source| Error::InvalidHeaderValue {
        name: name.to_owned(),
        source,
    })
}

pub(crate) fn phase_timeout(
    per_attempt_timeout: Duration,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Duration> {
    let Some(total_timeout) = total_timeout else {
        return Some(per_attempt_timeout);
    };

    let elapsed = request_started_at.elapsed();
    if elapsed >= total_timeout {
        return None;
    }

    let remaining = total_timeout - elapsed;
    Some(per_attempt_timeout.min(remaining))
}

pub(crate) fn bounded_retry_delay(
    retry_delay: Duration,
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Duration> {
    let Some(total_timeout) = total_timeout else {
        return Some(retry_delay);
    };

    let elapsed = request_started_at.elapsed();
    if elapsed >= total_timeout {
        return None;
    }

    let remaining = total_timeout - elapsed;
    if retry_delay >= remaining {
        return None;
    }
    Some(retry_delay)
}

pub(crate) fn deadline_exceeded_error(
    total_timeout: Option<Duration>,
    method: &Method,
    uri: &str,
) -> Error {
    let timeout_ms = total_timeout.map(|item| item.as_millis()).unwrap_or(0);
    Error::DeadlineExceeded {
        timeout_ms,
        method: method.clone(),
        uri: uri.to_owned(),
    }
}

pub(crate) fn parse_retry_after(headers: &HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?;
    let raw_value = value.to_str().ok()?.trim();
    if let Ok(seconds) = raw_value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let date = httpdate::parse_http_date(raw_value).ok()?;
    match date.duration_since(now) {
        Ok(duration) => Some(duration),
        Err(_) => Some(Duration::ZERO),
    }
}

pub(crate) fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

pub(crate) fn redirect_method(method: &Method, status: StatusCode) -> Method {
    match status {
        StatusCode::SEE_OTHER => Method::GET,
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if *method == Method::POST => Method::GET,
        _ => method.clone(),
    }
}

pub(crate) fn redirect_location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

pub(crate) fn default_port(uri: &Uri) -> Option<u16> {
    uri.port_u16().or_else(|| match uri.scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    })
}

pub(crate) fn rate_limit_bucket_key(uri: &Uri) -> Option<String> {
    let host = uri.host()?.to_ascii_lowercase();
    let Some(port) = default_port(uri) else {
        return Some(host);
    };
    Some(format!("{host}:{port}"))
}

pub(crate) fn same_origin(left: &Uri, right: &Uri) -> bool {
    let left_scheme = left.scheme_str().unwrap_or_default();
    let right_scheme = right.scheme_str().unwrap_or_default();
    if !left_scheme.eq_ignore_ascii_case(right_scheme) {
        return false;
    }

    let left_host = left.host().unwrap_or_default();
    let right_host = right.host().unwrap_or_default();
    if !left_host.eq_ignore_ascii_case(right_host) {
        return false;
    }

    default_port(left) == default_port(right)
}

pub(crate) fn resolve_redirect_uri(current_uri: &Uri, location: &str) -> Option<Uri> {
    let base = url::Url::parse(&current_uri.to_string()).ok()?;
    let joined = base.join(location).ok()?;
    joined.as_str().parse().ok()
}

pub(crate) fn sanitize_headers_for_redirect(
    headers: &mut HeaderMap,
    method_changed_to_get: bool,
    same_origin_redirect: bool,
) {
    if method_changed_to_get {
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_TYPE);
    }
    if !same_origin_redirect {
        headers.remove(AUTHORIZATION);
        headers.remove(COOKIE);
    }
}

pub(crate) fn truncate_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if text.chars().count() <= MAX_ERROR_BODY_LEN {
        return text.into_owned();
    }

    let truncated: String = text.chars().take(MAX_ERROR_BODY_LEN).collect();
    format!("{truncated}...(truncated)")
}
