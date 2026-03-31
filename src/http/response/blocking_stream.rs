use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;

use crate::blocking_client::limiters::{GlobalRequestPermit, HostRequestPermit};
use crate::content_encoding::{
    decode_content_encoded_body_limited, should_decode_content_encoded_body,
};
use crate::error::{Error, TimeoutPhase};
use crate::extensions::Clock;

use super::{
    Response, StreamCompletion, StreamLifecycle, deadline_elapsed, deadline_limits_wait,
    deadline_within_slack,
};

fn map_read_error(
    source: std::io::Error,
    method: &http::Method,
    uri: &str,
    timeout_ms: u128,
) -> Error {
    if let Some(ureq_error) = source
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ureq::Error>())
        && let ureq::Error::Timeout(timeout) = ureq_error
    {
        let _ = timeout;
        return Error::Timeout {
            phase: TimeoutPhase::ResponseBody,
            timeout_ms,
            method: method.clone(),
            uri: uri.to_owned(),
        };
    }

    Error::ReadBody {
        source: Box::new(source),
    }
}

fn deadline_exceeded_error(
    method: &http::Method,
    uri: &str,
    timeout_ms: u128,
    total_timeout_ms: Option<u128>,
) -> Error {
    Error::DeadlineExceeded {
        timeout_ms: total_timeout_ms.unwrap_or_else(|| timeout_ms.max(1)),
        method: method.clone(),
        uri: uri.to_owned(),
    }
}

/// Streaming blocking response body with request metadata.
///
/// Use this when you want to consume large responses incrementally without
/// buffering them into memory first.
///
/// See also `examples/blocking_streaming.rs`.
#[cfg_attr(
    docsrs,
    doc(cfg(any(
        feature = "blocking-tls-rustls-ring",
        feature = "blocking-tls-rustls-aws-lc-rs",
        feature = "blocking-tls-native"
    )))
)]
pub struct BlockingResponseStream {
    status: StatusCode,
    headers: HeaderMap,
    body: ureq::Body,
    method: http::Method,
    uri_raw: String,
    uri_redacted: String,
    timeout_ms: u128,
    total_timeout_ms: Option<u128>,
    deadline_at: Option<Instant>,
    deadline_slack: Duration,
    clock: Arc<dyn Clock>,
    lifecycle: Option<StreamLifecycle>,
    _global_permit: Option<GlobalRequestPermit>,
    _host_permit: Option<HostRequestPermit>,
}

pub(crate) struct BlockingResponseStreamContext {
    pub(crate) method: http::Method,
    pub(crate) uri_raw: String,
    pub(crate) uri_redacted: String,
    pub(crate) timeout_ms: u128,
    pub(crate) total_timeout_ms: Option<u128>,
    pub(crate) deadline_at: Option<Instant>,
    pub(crate) deadline_slack: Duration,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) lifecycle: Option<StreamLifecycle>,
    pub(crate) global_permit: Option<GlobalRequestPermit>,
    pub(crate) host_permit: Option<HostRequestPermit>,
}

impl BlockingResponseStream {
    pub(crate) fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: ureq::Body,
        context: BlockingResponseStreamContext,
    ) -> Self {
        let BlockingResponseStreamContext {
            method,
            uri_raw,
            uri_redacted,
            timeout_ms,
            total_timeout_ms,
            deadline_at,
            deadline_slack,
            clock,
            lifecycle,
            global_permit,
            host_permit,
        } = context;
        Self {
            status,
            headers,
            body,
            method,
            uri_raw,
            uri_redacted,
            timeout_ms: timeout_ms.max(1),
            total_timeout_ms,
            deadline_at,
            deadline_slack,
            clock,
            lifecycle,
            _global_permit: global_permit,
            _host_permit: host_permit,
        }
    }

    pub(crate) fn attach_completion(&mut self, completion: StreamCompletion) {
        super::attach_completion(&mut self.lifecycle, completion);
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the originating request method.
    pub fn method(&self) -> &http::Method {
        &self.method
    }

    /// Returns the original request URI, including query string.
    pub fn uri(&self) -> &str {
        self.uri_raw()
    }

    /// Returns the original request URI, including query string.
    pub fn uri_raw(&self) -> &str {
        &self.uri_raw
    }

    /// Returns a redacted URI suitable for logs and errors.
    ///
    /// The redacted form omits the query string to reduce accidental
    /// leakage of sensitive parameters.
    pub fn uri_redacted(&self) -> &str {
        &self.uri_redacted
    }

    fn response_body_too_large_error(&self, limit_bytes: usize, actual_bytes: usize) -> Error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            method: self.method.clone(),
            uri: self.uri_redacted.clone(),
        }
    }

    fn write_error(&self, source: std::io::Error) -> Error {
        super::write_body_error(&self.method, &self.uri_redacted, source)
    }

    fn current_read_is_deadline_limited(&self) -> bool {
        let Some(deadline_at) = self.deadline_at else {
            return false;
        };
        deadline_limits_wait(
            Duration::from_millis(self.timeout_ms.max(1) as u64),
            deadline_at,
            self.clock.now_monotonic(),
        )
    }

    fn map_read_error(&self, source: std::io::Error, deadline_limited: bool) -> Error {
        let mapped = map_read_error(source, &self.method, &self.uri_redacted, self.timeout_ms);
        let now = self.clock.now_monotonic();
        if matches!(mapped, Error::Timeout { .. })
            && self.deadline_at.is_some_and(|deadline_at| {
                deadline_elapsed(deadline_at, now)
                    || (deadline_limited
                        && deadline_within_slack(deadline_at, now, self.deadline_slack))
            })
        {
            return deadline_exceeded_error(
                &self.method,
                &self.uri_redacted,
                self.timeout_ms,
                self.total_timeout_ms,
            );
        }
        mapped
    }

    fn ensure_within_deadline(&self) -> crate::Result<()> {
        if let Some(deadline_at) = self.deadline_at
            && deadline_elapsed(deadline_at, self.clock.now_monotonic())
        {
            return Err(deadline_exceeded_error(
                &self.method,
                &self.uri_redacted,
                self.timeout_ms,
                self.total_timeout_ms,
            ));
        }
        Ok(())
    }

    /// Reads the next chunk of body bytes into `buffer`.
    ///
    /// Returns `0` at end of stream.
    pub fn read_chunk(&mut self, buffer: &mut [u8]) -> crate::Result<usize> {
        if let Err(error) = self.ensure_within_deadline() {
            self.complete_error(&error);
            return Err(error);
        }
        let deadline_limited = self.current_read_is_deadline_limited();
        let read = self
            .body
            .as_reader()
            .read(buffer)
            .map_err(|source| self.map_read_error(source, deadline_limited));
        match read {
            Ok(read) => {
                if let Err(error) = self.ensure_within_deadline() {
                    self.complete_error(&error);
                    return Err(error);
                }
                if read == 0 {
                    self.complete_success();
                }
                Ok(read)
            }
            Err(error) => {
                self.complete_error(&error);
                Err(error)
            }
        }
    }

    fn write_chunk<W>(&mut self, writer: &mut W, chunk: &[u8]) -> crate::Result<()>
    where
        W: Write + ?Sized,
    {
        if let Err(source) = writer.write_all(chunk) {
            let error = self.write_error(source);
            self.complete_error(&error);
            return Err(error);
        }
        Ok(())
    }

    fn flush_writer<W>(&mut self, writer: &mut W) -> crate::Result<()>
    where
        W: Write + ?Sized,
    {
        if let Err(source) = writer.flush() {
            let error = self.write_error(source);
            self.complete_error(&error);
            return Err(error);
        }
        Ok(())
    }

    /// Copies the streamed body into `writer`.
    ///
    /// See also `examples/blocking_streaming.rs`.
    pub fn copy_to_writer<W>(mut self, writer: &mut W) -> crate::Result<u64>
    where
        W: Write + ?Sized,
    {
        let mut chunk = [0_u8; 8192];
        let mut copied = 0_u64;
        loop {
            let read = self.read_chunk(&mut chunk)?;
            if read == 0 {
                break;
            }
            self.write_chunk(writer, &chunk[..read])?;
            copied = copied.saturating_add(read as u64);
        }
        self.flush_writer(writer)?;
        self.complete_success();
        Ok(copied)
    }

    /// Copies the streamed body into `writer`, enforcing `max_bytes`.
    pub fn copy_to_writer_limited<W>(
        mut self,
        writer: &mut W,
        max_bytes: usize,
    ) -> crate::Result<u64>
    where
        W: Write + ?Sized,
    {
        let max_bytes = max_bytes.max(1);
        let mut chunk = [0_u8; 8192];
        let mut copied = 0_u64;
        loop {
            let read = self.read_chunk(&mut chunk)?;
            if read == 0 {
                break;
            }
            copied = copied.saturating_add(read as u64);
            if copied > max_bytes as u64 {
                let error = self.response_body_too_large_error(max_bytes, copied as usize);
                self.complete_error(&error);
                return Err(error);
            }
            self.write_chunk(writer, &chunk[..read])?;
        }
        self.flush_writer(writer)?;
        self.complete_success();
        Ok(copied)
    }

    /// Buffers the stream into memory, enforcing `max_bytes`.
    pub fn into_bytes_limited(mut self, max_bytes: usize) -> crate::Result<Bytes> {
        let max_bytes = max_bytes.max(1);
        let mut chunk = [0_u8; 8192];
        let mut collected = Vec::new();
        let mut total_len = 0_usize;

        loop {
            let read = self.read_chunk(&mut chunk)?;
            if read == 0 {
                break;
            }
            total_len = total_len.saturating_add(read);
            if total_len > max_bytes {
                let error = self.response_body_too_large_error(max_bytes, total_len);
                self.complete_error(&error);
                return Err(error);
            }
            collected.extend_from_slice(&chunk[..read]);
        }
        self.complete_success();
        Ok(Bytes::from(collected))
    }

    /// Buffers and decodes the stream into a [`Response`], enforcing `max_bytes`.
    ///
    /// See also `examples/blocking_streaming.rs`.
    pub fn into_response_limited(mut self, max_bytes: usize) -> crate::Result<Response> {
        let max_bytes = max_bytes.max(1);
        let mut chunk = [0_u8; 8192];
        let mut collected = Vec::new();
        let mut total_len = 0_usize;

        loop {
            let read = self.read_chunk(&mut chunk)?;
            if read == 0 {
                break;
            }
            total_len = total_len.saturating_add(read);
            if total_len > max_bytes {
                let error = self.response_body_too_large_error(max_bytes, total_len);
                self.complete_error(&error);
                return Err(error);
            }
            collected.extend_from_slice(&chunk[..read]);
        }
        let body = Bytes::from(collected);
        let status = self.status;
        let method = self.method.clone();
        let uri_redacted = self.uri_redacted.clone();
        let mut headers = std::mem::take(&mut self.headers);
        let should_decode = should_decode_content_encoded_body(&method, status, body.len());
        let body = if should_decode {
            decode_content_encoded_body_limited(body, &headers, max_bytes).map_err(|error| {
                let error = super::map_decode_body_error(error, &method, &uri_redacted, max_bytes);
                self.complete_error(&error);
                error
            })?
        } else {
            body
        };
        if should_decode && headers.contains_key(super::CONTENT_ENCODING) {
            headers.remove(super::CONTENT_ENCODING);
            headers.remove(super::CONTENT_LENGTH);
        }
        self.complete_success();
        Ok(Response::new(status, headers, body))
    }

    /// Buffers the stream as UTF-8 text, enforcing `max_bytes`.
    pub fn into_text_limited(self, max_bytes: usize) -> crate::Result<String> {
        let response = self.into_response_limited(max_bytes)?;
        response.text().map(ToOwned::to_owned)
    }

    /// Buffers the stream as lossy UTF-8 text, enforcing `max_bytes`.
    pub fn into_text_lossy_limited(self, max_bytes: usize) -> crate::Result<String> {
        let response = self.into_response_limited(max_bytes)?;
        Ok(response.text_lossy())
    }

    /// Buffers and deserializes the stream from JSON, enforcing `max_bytes`.
    pub fn into_json_limited<T>(self, max_bytes: usize) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.into_response_limited(max_bytes)?;
        response.json()
    }

    fn complete_success(&mut self) {
        super::complete_success(&mut self.lifecycle);
    }

    fn complete_error(&mut self, error: &Error) {
        super::complete_error(&mut self.lifecycle, error);
    }
}

impl std::fmt::Debug for BlockingResponseStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockingResponseStream")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("method", &self.method)
            .field("uri_raw", &self.uri_raw)
            .field("uri_redacted", &self.uri_redacted)
            .field("timeout_ms", &self.timeout_ms)
            .field("total_timeout_ms", &self.total_timeout_ms)
            .field("deadline_at", &self.deadline_at)
            .field("deadline_slack", &self.deadline_slack)
            .field("has_lifecycle", &self.lifecycle.is_some())
            .finish()
    }
}

impl Read for BlockingResponseStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.read_chunk(buffer)
            .map_err(super::into_stream_read_io_error)
    }
}
