use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use http::header::{ACCEPT_ENCODING, HeaderName, HeaderValue, RETRY_AFTER};
use http::{HeaderMap, Method, Uri};

use crate::error::{HttpClientError, TransportErrorKind};

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

pub(crate) fn ensure_accept_encoding(headers: &mut HeaderMap) {
    if !headers.contains_key(ACCEPT_ENCODING) {
        headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, br, deflate, zstd"),
        );
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

pub(crate) fn resolve_uri(base_url: &str, path: &str) -> Result<(String, Uri), HttpClientError> {
    let uri_text = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else {
        join_base_path(base_url, path)
    };
    let uri = uri_text.parse().map_err(|_| HttpClientError::InvalidUri {
        uri: uri_text.clone(),
    })?;
    Ok((uri_text, uri))
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

pub(crate) fn parse_header_name(name: &str) -> Result<HeaderName, HttpClientError> {
    name.parse()
        .map_err(|source| HttpClientError::InvalidHeaderName {
            name: name.to_owned(),
            source,
        })
}

pub(crate) fn parse_header_value(name: &str, value: &str) -> Result<HeaderValue, HttpClientError> {
    value
        .parse()
        .map_err(|source| HttpClientError::InvalidHeaderValue {
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
) -> HttpClientError {
    let timeout_ms = total_timeout.map(|item| item.as_millis()).unwrap_or(0);
    HttpClientError::DeadlineExceeded {
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

pub(crate) fn truncate_body(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if text.chars().count() <= MAX_ERROR_BODY_LEN {
        return text.into_owned();
    }

    let truncated: String = text.chars().take(MAX_ERROR_BODY_LEN).collect();
    format!("{truncated}...(truncated)")
}
