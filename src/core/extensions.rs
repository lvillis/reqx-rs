use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, Method};

use crate::content_encoding::{DecodeContentEncodingError, decode_content_encoded_body_limited};
use crate::error::Error;
use crate::retry::RetryPolicy;

pub trait EndpointSelector: Send + Sync {
    fn select_base_url(
        &self,
        method: &Method,
        path: &str,
        configured_base_url: &str,
    ) -> crate::Result<String>;
}

#[derive(Debug, Default)]
pub struct PrimaryEndpointSelector;

impl EndpointSelector for PrimaryEndpointSelector {
    fn select_base_url(
        &self,
        _method: &Method,
        _path: &str,
        configured_base_url: &str,
    ) -> crate::Result<String> {
        Ok(configured_base_url.to_owned())
    }
}

#[derive(Debug)]
pub struct RoundRobinEndpointSelector {
    endpoints: Vec<String>,
    next: AtomicUsize,
}

impl RoundRobinEndpointSelector {
    pub fn new<I, S>(endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints = endpoints.into_iter().map(Into::into).collect();
        Self {
            endpoints,
            next: AtomicUsize::new(0),
        }
    }
}

impl EndpointSelector for RoundRobinEndpointSelector {
    fn select_base_url(
        &self,
        _method: &Method,
        _path: &str,
        configured_base_url: &str,
    ) -> crate::Result<String> {
        if self.endpoints.is_empty() {
            return Ok(configured_base_url.to_owned());
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        Ok(self.endpoints[index % self.endpoints.len()].clone())
    }
}

pub trait BackoffSource: Send + Sync {
    fn backoff_for_retry(&self, retry_policy: &RetryPolicy, attempt: usize) -> Duration;
}

#[derive(Debug, Default)]
pub struct PolicyBackoffSource;

impl BackoffSource for PolicyBackoffSource {
    fn backoff_for_retry(&self, retry_policy: &RetryPolicy, attempt: usize) -> Duration {
        RetryPolicy::backoff_for_retry(retry_policy, attempt)
    }
}

pub trait Clock: Send + Sync {
    fn now_system(&self) -> SystemTime;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait OtelPathNormalizer: Send + Sync {
    fn normalize_path(&self, path: &str) -> String;
}

#[derive(Debug, Default)]
pub struct StandardOtelPathNormalizer;

impl OtelPathNormalizer for StandardOtelPathNormalizer {
    fn normalize_path(&self, path: &str) -> String {
        let normalized = if path.is_empty() { "/" } else { path };
        let mut collapsed = String::with_capacity(normalized.len().min(128));
        let mut first = true;
        for segment in normalized.split('/') {
            if first {
                first = false;
                if normalized.starts_with('/') {
                    collapsed.push('/');
                }
                if segment.is_empty() {
                    continue;
                }
            } else if !collapsed.ends_with('/') {
                collapsed.push('/');
            }
            if segment.is_empty() {
                continue;
            }
            collapsed.push_str(normalize_path_segment(segment));
        }
        if collapsed.is_empty() {
            collapsed.push('/');
        }
        if collapsed.len() > 128 {
            collapsed = truncate_path_at_segment_boundary(&collapsed, 128);
        }
        collapsed
    }
}

fn truncate_path_at_segment_boundary(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_owned();
    }

    let mut cutoff = max_len.min(path.len());
    while cutoff > 0 && !path.is_char_boundary(cutoff) {
        cutoff = cutoff.saturating_sub(1);
    }
    if cutoff == 0 {
        return "/".to_owned();
    }

    let cut_in_middle_of_segment = cutoff < path.len() && !path[cutoff..].starts_with('/');
    if !cut_in_middle_of_segment {
        let kept = path[..cutoff].trim_end_matches('/');
        return if kept.is_empty() {
            "/".to_owned()
        } else {
            kept.to_owned()
        };
    }

    let prefix = path[..cutoff].trim_end_matches('/');
    if prefix.is_empty() {
        return "/".to_owned();
    }
    if let Some(last_separator) = prefix.rfind('/') {
        if last_separator == 0 {
            prefix.to_owned()
        } else {
            prefix[..last_separator].to_owned()
        }
    } else {
        "/".to_owned()
    }
}

fn normalize_path_segment(segment: &str) -> &str {
    if is_uuid_like(segment) {
        return ":uuid";
    }
    if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return ":hex";
    }
    if segment.len() >= 12 && segment.chars().all(|c| c.is_ascii_digit()) {
        return ":int";
    }
    if segment.len() >= 24 && looks_like_token(segment) {
        return ":token";
    }
    segment
}

fn is_uuid_like(segment: &str) -> bool {
    if segment.len() != 36 {
        return false;
    }
    for (index, character) in segment.chars().enumerate() {
        let is_hyphen_position = matches!(index, 8 | 13 | 18 | 23);
        if is_hyphen_position {
            if character != '-' {
                return false;
            }
        } else if !character.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn looks_like_token(segment: &str) -> bool {
    segment.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '~' | '.' | '=' | '+')
    })
}

pub trait BodyCodec: Send + Sync {
    fn decode_response_body_limited(
        &self,
        body: Bytes,
        headers: &HeaderMap,
        max_response_body_bytes: usize,
        method: &Method,
        uri: &str,
    ) -> Result<Bytes, Error>;
}

#[derive(Debug, Default)]
pub struct StandardBodyCodec;

impl BodyCodec for StandardBodyCodec {
    fn decode_response_body_limited(
        &self,
        body: Bytes,
        headers: &HeaderMap,
        max_response_body_bytes: usize,
        method: &Method,
        uri: &str,
    ) -> Result<Bytes, Error> {
        decode_content_encoded_body_limited(body, headers, max_response_body_bytes)
            .map_err(|error| map_decode_error(error, max_response_body_bytes, method, uri))
    }
}

fn map_decode_error(
    error: DecodeContentEncodingError,
    max_response_body_bytes: usize,
    method: &Method,
    uri: &str,
) -> Error {
    match error {
        DecodeContentEncodingError::Decode { encoding, message } => Error::DecodeContentEncoding {
            encoding,
            message,
            method: method.clone(),
            uri: uri.to_owned(),
        },
        DecodeContentEncodingError::TooLarge { actual_bytes } => Error::ResponseBodyTooLarge {
            limit_bytes: max_response_body_bytes,
            actual_bytes,
            method: method.clone(),
            uri: uri.to_owned(),
        },
    }
}
