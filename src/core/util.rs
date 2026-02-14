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

fn ensure_accept_encoding(method: &Method, headers: &mut HeaderMap, value: &'static str) {
    if *method == Method::HEAD {
        return;
    }
    if !headers.contains_key(ACCEPT_ENCODING) {
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static(value));
    }
}

#[cfg(feature = "_async")]
pub(crate) fn ensure_accept_encoding_async(method: &Method, headers: &mut HeaderMap) {
    ensure_accept_encoding(method, headers, "gzip, br, deflate, zstd");
}

#[cfg(feature = "_blocking")]
pub(crate) fn ensure_accept_encoding_blocking(method: &Method, headers: &mut HeaderMap) {
    ensure_accept_encoding(method, headers, "gzip, br, deflate, zstd");
}

fn invalid_base_url_error(base_url: &str) -> Error {
    Error::InvalidUri {
        uri: redact_uri_for_logs(base_url),
    }
}

fn invalid_proxy_uri_error(proxy_uri: &Uri, message: impl Into<String>) -> Error {
    Error::InvalidProxyConfig {
        proxy_uri: redact_uri_for_logs(&proxy_uri.to_string()),
        message: message.into(),
    }
}

fn uri_has_userinfo(uri: &Uri) -> bool {
    uri.authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
}

fn strip_query_and_fragment(uri_text: &str) -> &str {
    let query_index = uri_text.find('?');
    let fragment_index = uri_text.find('#');
    let cutoff = match (query_index, fragment_index) {
        (Some(query), Some(fragment)) => query.min(fragment),
        (Some(query), None) => query,
        (None, Some(fragment)) => fragment,
        (None, None) => uri_text.len(),
    };
    &uri_text[..cutoff]
}

fn redact_userinfo_in_authority(uri_text: &str) -> String {
    fn redact_with_prefix(prefix: &str, rest: &str) -> Option<String> {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let (authority, suffix) = rest.split_at(authority_end);
        let at_index = authority.rfind('@')?;
        let host_port = &authority[at_index + 1..];
        if host_port.is_empty() {
            return None;
        }
        Some(format!("{prefix}{host_port}{suffix}"))
    }

    if let Some(scheme_separator) = uri_text.find("://") {
        let prefix_end = scheme_separator + 3;
        let (prefix, rest) = uri_text.split_at(prefix_end);
        if let Some(redacted) = redact_with_prefix(prefix, rest) {
            return redacted;
        }
        return uri_text.to_owned();
    }

    if let Some(rest) = uri_text.strip_prefix("//")
        && let Some(redacted) = redact_with_prefix("//", rest)
    {
        return redacted;
    }

    uri_text.to_owned()
}

fn redact_non_authority_credentials(uri_text: &str) -> String {
    let Some((scheme, remainder)) = uri_text.split_once(':') else {
        return uri_text.to_owned();
    };
    let redactable_scheme = matches!(
        scheme.to_ascii_lowercase().as_str(),
        "mailto" | "sip" | "sips"
    );
    if !redactable_scheme {
        return uri_text.to_owned();
    }
    if remainder.starts_with("//") {
        return uri_text.to_owned();
    }

    let Some(at_index) = remainder.rfind('@') else {
        return uri_text.to_owned();
    };
    let credential_like_prefix = &remainder[..at_index];
    if credential_like_prefix.is_empty() {
        return uri_text.to_owned();
    }
    if !credential_like_prefix.contains(':')
        && !credential_like_prefix.to_ascii_lowercase().contains("%3a")
    {
        return uri_text.to_owned();
    }

    let suffix = &remainder[at_index + 1..];
    format!("{scheme}:<redacted>@{suffix}")
}

fn is_token_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '~' | '+' | '=')
}

fn is_token_like(segment: &str) -> bool {
    !segment.is_empty() && segment.chars().all(is_token_char)
}

fn split_credential_like_segment(segment: &str) -> Option<(&str, &str)> {
    let (left, right) = segment.split_once(':')?;
    if left.is_empty() || right.is_empty() {
        return None;
    }
    if left.len() < 3 || right.len() < 6 {
        return None;
    }
    if !is_token_like(left) || !is_token_like(right) {
        return None;
    }
    Some((left, right))
}

fn redact_sensitive_path_segments(parsed: &mut url::Url) {
    let Some(mut path_segments) = parsed
        .path_segments()
        .map(|segments| segments.map(ToOwned::to_owned).collect::<Vec<_>>())
    else {
        return;
    };
    if path_segments.is_empty() {
        return;
    }

    let mut redacted = false;
    for segment in &mut path_segments {
        if let Some((left, _)) = split_credential_like_segment(segment) {
            *segment = format!("{left}:redacted");
            redacted = true;
        }
    }
    if !redacted {
        return;
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

pub(crate) fn redact_uri_for_logs(uri_text: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(uri_text) else {
        let stripped = strip_query_and_fragment(uri_text);
        let authority_redacted = redact_userinfo_in_authority(stripped);
        return redact_non_authority_credentials(&authority_redacted);
    };

    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    redact_sensitive_path_segments(&mut parsed);

    let serialized = parsed.to_string();
    let authority_redacted = redact_userinfo_in_authority(&serialized);
    redact_non_authority_credentials(&authority_redacted)
}

pub(crate) fn resolve_uri(base_url: &str, path: &str) -> Result<(String, Uri), Error> {
    let uri_text = match path.parse::<Uri>() {
        Ok(uri) if uri.host().is_some() => {
            let Some(scheme) = uri.scheme_str() else {
                return Err(Error::InvalidUri {
                    uri: redact_uri_for_logs(path),
                });
            };
            if uri_has_userinfo(&uri) {
                return Err(Error::InvalidUri {
                    uri: redact_uri_for_logs(path),
                });
            }
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
                path.to_owned()
            } else {
                return Err(Error::InvalidUri {
                    uri: redact_uri_for_logs(path),
                });
            }
        }
        _ => join_base_path(base_url, path),
    };
    let uri = uri_text.parse().map_err(|_| Error::InvalidUri {
        uri: redact_uri_for_logs(&uri_text),
    })?;
    if uri_has_userinfo(&uri) {
        return Err(Error::InvalidUri {
            uri: redact_uri_for_logs(&uri_text),
        });
    }
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

pub(crate) fn validate_http_proxy_uri(proxy_uri: &Uri) -> Result<(), Error> {
    let Some(scheme) = proxy_uri.scheme_str() else {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must include an explicit scheme",
        ));
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must use http scheme",
        ));
    }
    if proxy_uri.host().is_none() {
        return Err(invalid_proxy_uri_error(
            proxy_uri,
            "http_proxy URI must include host",
        ));
    }
    if let Some(path_and_query) = proxy_uri.path_and_query() {
        let path = path_and_query.path();
        if !path.is_empty() && path != "/" {
            return Err(invalid_proxy_uri_error(
                proxy_uri,
                "http_proxy URI must not include path segments",
            ));
        }
        if path_and_query.query().is_some() {
            return Err(invalid_proxy_uri_error(
                proxy_uri,
                "http_proxy URI must not include query parameters",
            ));
        }
    }
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
    let mut text = error.to_string().to_ascii_lowercase();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push(' ');
        text.push_str(&cause.to_string().to_ascii_lowercase());
        source = cause.source();
    }
    classify_transport_error_text(&text, error.is_connect())
}

#[cfg(feature = "_async")]
fn classify_transport_error_text(text: &str, is_connect_path: bool) -> TransportErrorKind {
    const DNS_MARKERS: &[&str] = &[
        "name or service not known",
        "failed to lookup address",
        "no such host",
        "temporary failure in name resolution",
        "nodename nor servname provided",
        "dns lookup failed",
    ];
    const TLS_MARKERS: &[&str] = &[
        "tls handshake",
        "certificate verify",
        "certificate unknown",
        "invalid certificate",
        "self signed certificate",
        "x509",
        "pkix",
        "peer certificate",
    ];
    const CONNECT_MARKERS: &[&str] = &[
        "connection refused",
        "connection aborted",
        "not connected",
        "network unreachable",
        "host unreachable",
        "connect error",
        "proxy connect",
        "timed out while connecting",
        "connection timeout",
        "connect timeout",
    ];
    const READ_MARKERS: &[&str] = &[
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "incomplete message",
        "connection closed before message completed",
        "body write aborted",
    ];

    if contains_marker(text, DNS_MARKERS) || contains_word(text, "dns") {
        return TransportErrorKind::Dns;
    }
    if contains_marker(text, TLS_MARKERS)
        || contains_word(text, "tls")
        || contains_word(text, "ssl")
        || contains_word(text, "certificate")
    {
        return TransportErrorKind::Tls;
    }
    if contains_marker(text, CONNECT_MARKERS) {
        return TransportErrorKind::Connect;
    }
    if contains_marker(text, READ_MARKERS) {
        return TransportErrorKind::Read;
    }
    if is_connect_path && contains_marker(text, &["timed out", "timeout"]) {
        return TransportErrorKind::Connect;
    }
    if is_connect_path {
        // Unknown connect-path failures stay conservative to avoid retrying
        // configuration, policy, or handshake-class problems by mistake.
        return TransportErrorKind::Other;
    }
    TransportErrorKind::Other
}

#[cfg(feature = "_async")]
fn contains_marker(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

#[cfg(feature = "_async")]
fn contains_word(text: &str, word: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| token == word)
}

#[cfg(all(test, feature = "_async"))]
pub(crate) fn classify_transport_error_text_for_test(
    text: &str,
    is_connect_path: bool,
) -> TransportErrorKind {
    classify_transport_error_text(text, is_connect_path)
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

pub(crate) fn total_timeout_expired(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> bool {
    total_timeout.is_some_and(|timeout| request_started_at.elapsed() >= timeout)
}

pub(crate) fn total_timeout_deadline(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> Option<Instant> {
    total_timeout.and_then(|timeout| request_started_at.checked_add(timeout))
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

pub(crate) fn parse_retry_after_capped(
    headers: &HeaderMap,
    now: SystemTime,
    max_delay: Duration,
) -> Option<Duration> {
    parse_retry_after(headers, now).map(|delay| delay.min(max_delay))
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
    uri.port_u16().or_else(|| {
        let scheme = uri.scheme_str()?;
        if scheme.eq_ignore_ascii_case("https") {
            return Some(443);
        }
        if scheme.eq_ignore_ascii_case("http") {
            return Some(80);
        }
        None
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
    if !matches!(joined.scheme(), "http" | "https") {
        return None;
    }
    if !joined.username().is_empty() || joined.password().is_some() {
        return None;
    }
    let resolved: Uri = joined.as_str().parse().ok()?;
    if uri_has_userinfo(&resolved) {
        return None;
    }
    Some(resolved)
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
