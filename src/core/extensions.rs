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
