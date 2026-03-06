use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use hyper::body::{Body as HyperBody, Incoming};
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Sleep;

use crate::body::decode_content_encoded_body_limited;
use crate::content_encoding::should_decode_content_encoded_body;
use crate::error::{Error, TimeoutPhase};
use crate::extensions::Clock;
use crate::limiters::{GlobalRequestPermit, HostRequestPermit};

use super::{Response, StreamCompletion, StreamLifecycle, deadline_reached};

#[derive(Debug)]
pub(crate) struct StreamPermits {
    global: Option<GlobalRequestPermit>,
    host: Option<HostRequestPermit>,
}

impl StreamPermits {
    pub(crate) fn new(
        global: Option<GlobalRequestPermit>,
        host: Option<HostRequestPermit>,
    ) -> Self {
        Self { global, host }
    }
}

pub(crate) struct ResponseStreamContext {
    pub(crate) method: http::Method,
    pub(crate) uri_raw: String,
    pub(crate) uri_redacted: String,
    pub(crate) timeout_ms: u128,
    pub(crate) total_timeout_ms: Option<u128>,
    pub(crate) deadline_at: Option<Instant>,
    pub(crate) deadline_slack: Duration,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) lifecycle: Option<StreamLifecycle>,
    pub(crate) permits: StreamPermits,
}

struct StreamBody {
    inner: Incoming,
    method: http::Method,
    uri_redacted: String,
    timeout_ms: u128,
    total_timeout_ms: Option<u128>,
    deadline_at: Option<Instant>,
    deadline_slack: Duration,
    clock: Arc<dyn Clock>,
    frame_timeout: Option<Pin<Box<Sleep>>>,
    read_buffer: Bytes,
    lifecycle: Option<StreamLifecycle>,
    _global_permit: Option<GlobalRequestPermit>,
    _host_permit: Option<HostRequestPermit>,
}

impl StreamBody {
    fn new(inner: Incoming, context: ResponseStreamContext) -> Self {
        let ResponseStreamContext {
            method,
            uri_raw: _,
            uri_redacted,
            timeout_ms,
            total_timeout_ms,
            deadline_at,
            deadline_slack,
            clock,
            lifecycle,
            permits,
        } = context;
        Self {
            inner,
            method,
            uri_redacted,
            timeout_ms: timeout_ms.max(1),
            total_timeout_ms,
            deadline_at,
            deadline_slack,
            clock,
            frame_timeout: None,
            read_buffer: Bytes::new(),
            lifecycle,
            _global_permit: permits.global,
            _host_permit: permits.host,
        }
    }

    fn attach_completion(&mut self, completion: StreamCompletion) {
        super::attach_completion(&mut self.lifecycle, completion);
    }

    fn method(&self) -> &http::Method {
        &self.method
    }

    fn uri_redacted(&self) -> &str {
        &self.uri_redacted
    }

    fn response_body_timeout_error(&self) -> Error {
        Error::Timeout {
            phase: TimeoutPhase::ResponseBody,
            timeout_ms: self.timeout_ms.max(1),
            method: self.method.clone(),
            uri: self.uri_redacted.clone(),
        }
    }

    fn deadline_exceeded_error(&self) -> Error {
        Error::DeadlineExceeded {
            timeout_ms: self
                .total_timeout_ms
                .unwrap_or_else(|| self.timeout_ms.max(1)),
            method: self.method.clone(),
            uri: self.uri_redacted.clone(),
        }
    }

    fn response_body_too_large_error(&self, limit_bytes: usize, actual_bytes: usize) -> Error {
        Error::ResponseBodyTooLarge {
            limit_bytes,
            actual_bytes,
            method: self.method.clone(),
            uri: self.uri_redacted.clone(),
        }
    }

    fn write_error(&self, source: io::Error) -> Error {
        super::write_body_error(&self.method, &self.uri_redacted, source)
    }

    fn effective_frame_timeout(&self) -> crate::Result<Duration> {
        let phase_timeout = Duration::from_millis(self.timeout_ms.max(1) as u64);
        let Some(deadline_at) = self.deadline_at else {
            return Ok(phase_timeout);
        };
        let now = self.clock.now_monotonic();
        if deadline_reached(deadline_at, now, self.deadline_slack) {
            return Err(self.deadline_exceeded_error());
        }
        let remaining = deadline_at.saturating_duration_since(now);
        Ok(phase_timeout.min(remaining))
    }

    fn ensure_frame_timeout(&mut self) -> crate::Result<()> {
        if self.frame_timeout.is_none() {
            let timeout = self.effective_frame_timeout()?;
            self.frame_timeout = Some(Box::pin(tokio::time::sleep(timeout)));
        }
        Ok(())
    }

    fn poll_next_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Error>>> {
        loop {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    self.frame_timeout = None;
                    match frame.into_data() {
                        Ok(data) if data.is_empty() => continue,
                        Ok(data) => return Poll::Ready(Some(Ok(data))),
                        Err(_) => continue,
                    }
                }
                Poll::Ready(Some(Err(source))) => {
                    self.frame_timeout = None;
                    return Poll::Ready(Some(Err(Error::ReadBody {
                        source: Box::new(source),
                    })));
                }
                Poll::Ready(None) => {
                    self.frame_timeout = None;
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    if let Err(error) = self.ensure_frame_timeout() {
                        return Poll::Ready(Some(Err(error)));
                    }
                    if let Some(timer) = self.frame_timeout.as_mut()
                        && timer.as_mut().poll(cx).is_ready()
                    {
                        self.frame_timeout = None;
                        let error = if self.deadline_at.is_some_and(|deadline_at| {
                            deadline_reached(
                                deadline_at,
                                self.clock.now_monotonic(),
                                self.deadline_slack,
                            )
                        }) {
                            self.deadline_exceeded_error()
                        } else {
                            self.response_body_timeout_error()
                        };
                        return Poll::Ready(Some(Err(error)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    async fn next_chunk(&mut self) -> crate::Result<Option<Bytes>> {
        match poll_fn(|cx| Pin::new(&mut *self).poll_next_chunk(cx)).await {
            Some(Ok(chunk)) => Ok(Some(chunk)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    fn take_pending_chunk(&mut self) -> Option<Bytes> {
        if self.read_buffer.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.read_buffer))
        }
    }

    async fn read_raw_bytes_limited(&mut self, max_bytes: usize) -> crate::Result<Bytes> {
        let max_bytes = max_bytes.max(1);
        let mut collected = Vec::new();
        let mut total_len = 0_usize;

        if let Some(chunk) = self.take_pending_chunk() {
            total_len = total_len.saturating_add(chunk.len());
            if total_len > max_bytes {
                return Err(self.response_body_too_large_error(max_bytes, total_len));
            }
            collected.extend_from_slice(&chunk);
        }

        while let Some(chunk) = self.next_chunk().await? {
            total_len = total_len.saturating_add(chunk.len());
            if total_len > max_bytes {
                return Err(self.response_body_too_large_error(max_bytes, total_len));
            }
            collected.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(collected))
    }

    async fn write_chunk<W>(&mut self, writer: &mut W, chunk: &[u8]) -> crate::Result<()>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        if let Err(source) = writer.write_all(chunk).await {
            let error = self.write_error(source);
            self.complete_error(&error);
            return Err(error);
        }
        Ok(())
    }

    async fn flush_writer<W>(&mut self, writer: &mut W) -> crate::Result<()>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        if let Err(source) = writer.flush().await {
            let error = self.write_error(source);
            self.complete_error(&error);
            return Err(error);
        }
        Ok(())
    }

    async fn copy_to_writer<W>(&mut self, writer: &mut W) -> crate::Result<u64>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let mut copied = 0_u64;

        if let Some(chunk) = self.take_pending_chunk() {
            self.write_chunk(writer, &chunk).await?;
            copied = copied.saturating_add(chunk.len() as u64);
        }

        while let Some(chunk) = match self.next_chunk().await {
            Ok(chunk) => chunk,
            Err(error) => {
                self.complete_error(&error);
                return Err(error);
            }
        } {
            self.write_chunk(writer, &chunk).await?;
            copied = copied.saturating_add(chunk.len() as u64);
        }
        self.flush_writer(writer).await?;
        self.complete_success();
        Ok(copied)
    }

    async fn copy_to_writer_limited<W>(
        &mut self,
        writer: &mut W,
        max_bytes: usize,
    ) -> crate::Result<u64>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let max_bytes = max_bytes.max(1);
        let mut copied = 0_u64;

        if let Some(chunk) = self.take_pending_chunk() {
            copied = copied.saturating_add(chunk.len() as u64);
            if copied > max_bytes as u64 {
                let error = self.response_body_too_large_error(max_bytes, copied as usize);
                self.complete_error(&error);
                return Err(error);
            }
            self.write_chunk(writer, &chunk).await?;
        }

        while let Some(chunk) = match self.next_chunk().await {
            Ok(chunk) => chunk,
            Err(error) => {
                self.complete_error(&error);
                return Err(error);
            }
        } {
            copied = copied.saturating_add(chunk.len() as u64);
            if copied > max_bytes as u64 {
                let error = self.response_body_too_large_error(max_bytes, copied as usize);
                self.complete_error(&error);
                return Err(error);
            }
            self.write_chunk(writer, &chunk).await?;
        }
        self.flush_writer(writer).await?;
        self.complete_success();
        Ok(copied)
    }

    fn complete_success(&mut self) {
        super::complete_success(&mut self.lifecycle);
    }

    fn complete_error(&mut self, error: &Error) {
        super::complete_error(&mut self.lifecycle, error);
    }
}

impl std::fmt::Debug for StreamBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamBody")
            .field("method", &self.method)
            .field("uri_redacted", &self.uri_redacted)
            .field("timeout_ms", &self.timeout_ms)
            .field("total_timeout_ms", &self.total_timeout_ms)
            .field("deadline_at", &self.deadline_at)
            .field("deadline_slack", &self.deadline_slack)
            .field("has_frame_timeout", &self.frame_timeout.is_some())
            .field("read_buffer_len", &self.read_buffer.len())
            .field("has_lifecycle", &self.lifecycle.is_some())
            .finish()
    }
}

#[derive(Debug)]
pub struct ResponseStream {
    status: StatusCode,
    headers: HeaderMap,
    uri_raw: String,
    body: StreamBody,
}

impl ResponseStream {
    pub(crate) fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        context: ResponseStreamContext,
    ) -> Self {
        let uri_raw = context.uri_raw.clone();
        Self {
            status,
            headers,
            uri_raw,
            body: StreamBody::new(body, context),
        }
    }

    pub(crate) fn attach_completion(&mut self, completion: StreamCompletion) {
        self.body.attach_completion(completion);
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn method(&self) -> &http::Method {
        self.body.method()
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
        self.body.uri_redacted()
    }

    pub async fn into_bytes_limited(self, max_bytes: usize) -> crate::Result<Bytes> {
        let max_bytes = max_bytes.max(1);
        let mut this = self;
        match this.body.read_raw_bytes_limited(max_bytes).await {
            Ok(body) => {
                this.body.complete_success();
                Ok(body)
            }
            Err(error) => {
                this.body.complete_error(&error);
                Err(error)
            }
        }
    }

    pub async fn copy_to_writer<W>(mut self, writer: &mut W) -> crate::Result<u64>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        self.body.copy_to_writer(writer).await
    }

    pub async fn copy_to_writer_limited<W>(
        mut self,
        writer: &mut W,
        max_bytes: usize,
    ) -> crate::Result<u64>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        self.body.copy_to_writer_limited(writer, max_bytes).await
    }

    pub async fn into_response_limited(mut self, max_bytes: usize) -> crate::Result<Response> {
        let max_bytes = max_bytes.max(1);
        let method = self.body.method().clone();
        let uri_redacted = self.body.uri_redacted().to_owned();
        let body = match self.body.read_raw_bytes_limited(max_bytes).await {
            Ok(body) => body,
            Err(error) => {
                self.body.complete_error(&error);
                return Err(error);
            }
        };
        let should_decode = should_decode_content_encoded_body(&method, self.status, body.len());
        let body = if should_decode {
            match decode_content_encoded_body_limited(body, &self.headers, max_bytes) {
                Ok(body) => body,
                Err(error) => {
                    let error =
                        super::map_decode_body_error(error, &method, &uri_redacted, max_bytes);
                    self.body.complete_error(&error);
                    return Err(error);
                }
            }
        } else {
            body
        };
        if should_decode && self.headers.contains_key(super::CONTENT_ENCODING) {
            self.headers.remove(super::CONTENT_ENCODING);
            self.headers.remove(super::CONTENT_LENGTH);
        }
        self.body.complete_success();
        Ok(Response::new(self.status, self.headers, body))
    }

    pub async fn into_text_limited(self, max_bytes: usize) -> crate::Result<String> {
        let response = self.into_response_limited(max_bytes).await?;
        response.text().map(ToOwned::to_owned)
    }

    pub async fn into_text_lossy_limited(self, max_bytes: usize) -> crate::Result<String> {
        let response = self.into_response_limited(max_bytes).await?;
        Ok(response.text_lossy())
    }

    pub async fn into_json_limited<T>(self, max_bytes: usize) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.into_response_limited(max_bytes).await?;
        response.json()
    }
}

impl AsyncRead for StreamBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.read_buffer.is_empty() {
                let to_copy = self.read_buffer.len().min(buffer.remaining());
                let chunk = self.read_buffer.split_to(to_copy);
                buffer.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }

            match self.as_mut().poll_next_chunk(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.read_buffer = chunk;
                }
                Poll::Ready(Some(Err(error))) => {
                    self.complete_error(&error);
                    return Poll::Ready(Err(super::into_stream_read_io_error(error)));
                }
                Poll::Ready(None) => {
                    self.complete_success();
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncRead for ResponseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_read(cx, buffer)
    }
}
