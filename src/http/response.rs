use bytes::Bytes;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;

use crate::error::Error;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use crate::metrics::StreamCompletion;
use crate::util::truncate_body;

#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    pub(crate) fn new(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn body(&self) -> &Bytes {
        &self.body
    }

    pub fn text(&self) -> crate::Result<&str> {
        std::str::from_utf8(&self.body).map_err(|source| Error::DecodeText {
            source,
            body: truncate_body(&self.body),
        })
    }

    pub fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json<T>(&self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(&self.body).map_err(|source| Error::DeserializeJson {
            source,
            body: truncate_body(&self.body),
        })
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) trait StreamOutcomeHooks {
    fn complete_success(&mut self);

    fn complete_error(&mut self, error: &Error);

    fn complete_canceled(&mut self);
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamLifecycleState {
    Pending,
    Success,
    Error,
    Canceled,
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) struct StreamLifecycle {
    completion: Option<StreamCompletion>,
    hooks: Option<Box<dyn StreamOutcomeHooks + Send>>,
    state: StreamLifecycleState,
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
impl StreamLifecycle {
    pub(crate) fn new(hooks: Option<Box<dyn StreamOutcomeHooks + Send>>) -> Self {
        Self {
            completion: None,
            hooks,
            state: StreamLifecycleState::Pending,
        }
    }

    pub(crate) fn attach_completion(&mut self, completion: StreamCompletion) {
        self.completion = Some(completion);
    }

    pub(crate) fn complete_success(&mut self) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Success;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_success();
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_success();
        }
    }

    pub(crate) fn complete_error(&mut self, error: &Error) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Error;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_error(error);
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_error(error);
        }
    }

    pub(crate) fn complete_canceled(&mut self) {
        if self.state != StreamLifecycleState::Pending {
            return;
        }
        self.state = StreamLifecycleState::Canceled;
        if let Some(hooks) = &mut self.hooks {
            hooks.complete_canceled();
        }
        if let Some(completion) = &mut self.completion {
            completion.complete_canceled();
        }
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
impl std::fmt::Debug for StreamLifecycle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamLifecycle")
            .field("has_completion", &self.completion.is_some())
            .field("has_hooks", &self.hooks.is_some())
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
impl Drop for StreamLifecycle {
    fn drop(&mut self) {
        self.complete_canceled();
    }
}

#[cfg(feature = "_async")]
mod stream {
    use std::future::{Future, poll_fn};
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use hyper::body::{Body as HyperBody, Incoming};
    use serde::de::DeserializeOwned;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::time::Sleep;

    use crate::body::{DecodeContentEncodingError, decode_content_encoded_body_limited};
    use crate::content_encoding::should_decode_content_encoded_body;
    use crate::error::{Error, TimeoutPhase};
    use crate::limiters::{GlobalRequestPermit, HostRequestPermit};
    use crate::response::Response;

    fn map_decode_body_error(
        error: DecodeContentEncodingError,
        method: &http::Method,
        uri: &str,
        max_bytes: usize,
    ) -> Error {
        match error {
            DecodeContentEncodingError::Decode { encoding, message } => {
                Error::DecodeContentEncoding {
                    encoding,
                    method: method.clone(),
                    uri: uri.to_owned(),
                    message,
                }
            }
            DecodeContentEncodingError::TooLarge { actual_bytes } => Error::ResponseBodyTooLarge {
                limit_bytes: max_bytes,
                actual_bytes,
                method: method.clone(),
                uri: uri.to_owned(),
            },
        }
    }

    fn stream_read_io_error_kind(error: &Error) -> io::ErrorKind {
        match error {
            Error::Timeout { .. } | Error::DeadlineExceeded { .. } => io::ErrorKind::TimedOut,
            Error::ReadBody { source } => source
                .downcast_ref::<io::Error>()
                .map_or(io::ErrorKind::Other, io::Error::kind),
            _ => io::ErrorKind::Other,
        }
    }

    fn into_stream_read_io_error(error: Error) -> io::Error {
        let kind = stream_read_io_error_kind(&error);
        io::Error::new(kind, error)
    }

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

    #[derive(Debug)]
    pub(crate) struct ResponseStreamContext {
        pub(crate) method: http::Method,
        pub(crate) uri_raw: String,
        pub(crate) uri_redacted: String,
        pub(crate) timeout_ms: u128,
        pub(crate) total_timeout_ms: Option<u128>,
        pub(crate) deadline_at: Option<Instant>,
        pub(crate) lifecycle: Option<super::StreamLifecycle>,
        pub(crate) permits: StreamPermits,
    }

    #[derive(Debug)]
    struct StreamBody {
        inner: Incoming,
        method: http::Method,
        uri_redacted: String,
        timeout_ms: u128,
        total_timeout_ms: Option<u128>,
        deadline_at: Option<Instant>,
        frame_timeout: Option<Pin<Box<Sleep>>>,
        read_buffer: Bytes,
        lifecycle: Option<super::StreamLifecycle>,
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
                frame_timeout: None,
                read_buffer: Bytes::new(),
                lifecycle,
                _global_permit: permits.global,
                _host_permit: permits.host,
            }
        }

        fn attach_completion(&mut self, completion: super::StreamCompletion) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.attach_completion(completion);
            } else {
                let mut lifecycle = super::StreamLifecycle::new(None);
                lifecycle.attach_completion(completion);
                self.lifecycle = Some(lifecycle);
            }
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

        fn effective_frame_timeout(&self) -> crate::Result<Duration> {
            let phase_timeout = Duration::from_millis(self.timeout_ms.max(1) as u64);
            let Some(deadline_at) = self.deadline_at else {
                return Ok(phase_timeout);
            };
            let now = Instant::now();
            if now >= deadline_at {
                return Err(self.deadline_exceeded_error());
            }
            let remaining = deadline_at.duration_since(now);
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
                            let error = if self
                                .deadline_at
                                .is_some_and(|deadline_at| Instant::now() >= deadline_at)
                            {
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
                    return Err(Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    });
                }
                collected.extend_from_slice(&chunk);
            }

            while let Some(chunk) = self.next_chunk().await? {
                total_len = total_len.saturating_add(chunk.len());
                if total_len > max_bytes {
                    return Err(Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    });
                }
                collected.extend_from_slice(&chunk);
            }
            Ok(Bytes::from(collected))
        }

        async fn copy_to_writer<W>(&mut self, writer: &mut W) -> crate::Result<u64>
        where
            W: AsyncWrite + Unpin + Send + ?Sized,
        {
            let mut copied = 0_u64;

            if let Some(chunk) = self.take_pending_chunk() {
                if let Err(source) = writer.write_all(&chunk).await {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                copied = copied.saturating_add(chunk.len() as u64);
            }

            while let Some(chunk) = match self.next_chunk().await {
                Ok(chunk) => chunk,
                Err(error) => {
                    self.complete_error(&error);
                    return Err(error);
                }
            } {
                if let Err(source) = writer.write_all(&chunk).await {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                copied = copied.saturating_add(chunk.len() as u64);
            }
            if let Err(source) = writer.flush().await {
                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                self.complete_error(&error);
                return Err(error);
            }
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
                    let error = Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: copied as usize,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                if let Err(source) = writer.write_all(&chunk).await {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
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
                    let error = Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: copied as usize,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                if let Err(source) = writer.write_all(&chunk).await {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
            }
            if let Err(source) = writer.flush().await {
                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                self.complete_error(&error);
                return Err(error);
            }
            self.complete_success();
            Ok(copied)
        }

        fn complete_success(&mut self) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.complete_success();
            }
        }

        fn complete_error(&mut self, error: &Error) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.complete_error(error);
            }
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

        pub(crate) fn attach_completion(&mut self, completion: super::StreamCompletion) {
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
            let should_decode =
                should_decode_content_encoded_body(&method, self.status, body.len());
            let body = if should_decode {
                match decode_content_encoded_body_limited(body, &self.headers, max_bytes) {
                    Ok(body) => body,
                    Err(error) => {
                        let error = map_decode_body_error(error, &method, &uri_redacted, max_bytes);
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
                        return Poll::Ready(Err(into_stream_read_io_error(error)));
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
}

#[cfg(feature = "_blocking")]
mod blocking_stream {
    use std::io::{Read, Write};
    use std::time::Instant;

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use serde::de::DeserializeOwned;

    use crate::blocking_client::limiters::{GlobalRequestPermit, HostRequestPermit};
    use crate::content_encoding::{
        DecodeContentEncodingError, decode_content_encoded_body_limited,
        should_decode_content_encoded_body,
    };
    use crate::error::{Error, TimeoutPhase};
    use crate::response::Response;

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

    fn map_read_error_with_deadline(
        source: std::io::Error,
        method: &http::Method,
        uri: &str,
        timeout_ms: u128,
        deadline_at: Option<Instant>,
        total_timeout_ms: Option<u128>,
    ) -> Error {
        let mapped = map_read_error(source, method, uri, timeout_ms);
        if matches!(mapped, Error::Timeout { .. })
            && deadline_at.is_some_and(|deadline_at| Instant::now() >= deadline_at)
        {
            return deadline_exceeded_error(method, uri, timeout_ms, total_timeout_ms);
        }
        mapped
    }

    fn map_decode_error(
        error: DecodeContentEncodingError,
        method: &http::Method,
        uri: &str,
        max_bytes: usize,
    ) -> Error {
        match error {
            DecodeContentEncodingError::Decode { encoding, message } => {
                Error::DecodeContentEncoding {
                    encoding,
                    method: method.clone(),
                    uri: uri.to_owned(),
                    message,
                }
            }
            DecodeContentEncodingError::TooLarge { actual_bytes } => Error::ResponseBodyTooLarge {
                limit_bytes: max_bytes,
                actual_bytes,
                method: method.clone(),
                uri: uri.to_owned(),
            },
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

    fn ensure_within_deadline(
        deadline_at: Option<Instant>,
        method: &http::Method,
        uri: &str,
        timeout_ms: u128,
        total_timeout_ms: Option<u128>,
    ) -> crate::Result<()> {
        if let Some(deadline_at) = deadline_at
            && Instant::now() >= deadline_at
        {
            return Err(deadline_exceeded_error(
                method,
                uri,
                timeout_ms,
                total_timeout_ms,
            ));
        }
        Ok(())
    }

    fn stream_read_io_error_kind(error: &Error) -> std::io::ErrorKind {
        match error {
            Error::Timeout { .. } | Error::DeadlineExceeded { .. } => std::io::ErrorKind::TimedOut,
            Error::ReadBody { source } => source
                .downcast_ref::<std::io::Error>()
                .map_or(std::io::ErrorKind::Other, std::io::Error::kind),
            _ => std::io::ErrorKind::Other,
        }
    }

    fn into_stream_read_io_error(error: Error) -> std::io::Error {
        let kind = stream_read_io_error_kind(&error);
        std::io::Error::new(kind, error)
    }

    #[derive(Debug)]
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
        lifecycle: Option<super::StreamLifecycle>,
        _global_permit: Option<GlobalRequestPermit>,
        _host_permit: Option<HostRequestPermit>,
    }

    #[derive(Debug)]
    pub(crate) struct BlockingResponseStreamContext {
        pub(crate) method: http::Method,
        pub(crate) uri_raw: String,
        pub(crate) uri_redacted: String,
        pub(crate) timeout_ms: u128,
        pub(crate) total_timeout_ms: Option<u128>,
        pub(crate) deadline_at: Option<Instant>,
        pub(crate) lifecycle: Option<super::StreamLifecycle>,
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
                lifecycle,
                _global_permit: global_permit,
                _host_permit: host_permit,
            }
        }

        pub(crate) fn attach_completion(&mut self, completion: super::StreamCompletion) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.attach_completion(completion);
            } else {
                let mut lifecycle = super::StreamLifecycle::new(None);
                lifecycle.attach_completion(completion);
                self.lifecycle = Some(lifecycle);
            }
        }

        pub fn status(&self) -> StatusCode {
            self.status
        }

        pub fn headers(&self) -> &HeaderMap {
            &self.headers
        }

        pub fn method(&self) -> &http::Method {
            &self.method
        }

        /// Returns the original request URI, including query string.
        pub fn uri(&self) -> &str {
            &self.uri_raw
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

        pub fn read_chunk(&mut self, buffer: &mut [u8]) -> crate::Result<usize> {
            if let Err(error) = ensure_within_deadline(
                self.deadline_at,
                &self.method,
                &self.uri_redacted,
                self.timeout_ms,
                self.total_timeout_ms,
            ) {
                self.complete_error(&error);
                return Err(error);
            }
            let read = self.body.as_reader().read(buffer).map_err(|source| {
                map_read_error_with_deadline(
                    source,
                    &self.method,
                    &self.uri_redacted,
                    self.timeout_ms,
                    self.deadline_at,
                    self.total_timeout_ms,
                )
            });
            match read {
                Ok(read) => {
                    if let Err(error) = ensure_within_deadline(
                        self.deadline_at,
                        &self.method,
                        &self.uri_redacted,
                        self.timeout_ms,
                        self.total_timeout_ms,
                    ) {
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

        pub fn copy_to_writer<W>(mut self, writer: &mut W) -> crate::Result<u64>
        where
            W: Write + ?Sized,
        {
            // Stream raw wire bytes (content-encoding is not decoded on this path).
            let mut chunk = [0_u8; 8192];
            let mut copied = 0_u64;
            loop {
                let read = self.read_chunk(&mut chunk)?;
                if read == 0 {
                    break;
                }
                if let Err(source) = writer.write_all(&chunk[..read]) {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                copied = copied.saturating_add(read as u64);
            }
            if let Err(source) = writer.flush() {
                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                self.complete_error(&error);
                return Err(error);
            }
            self.complete_success();
            Ok(copied)
        }

        pub fn copy_to_writer_limited<W>(
            mut self,
            writer: &mut W,
            max_bytes: usize,
        ) -> crate::Result<u64>
        where
            W: Write + ?Sized,
        {
            // Stream raw wire bytes with a hard byte cap.
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
                    let error = Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: copied as usize,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                if let Err(source) = writer.write_all(&chunk[..read]) {
                    let error = Error::ReadBody {
                        source: Box::new(source),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
            }
            if let Err(source) = writer.flush() {
                let error = Error::ReadBody {
                    source: Box::new(source),
                };
                self.complete_error(&error);
                return Err(error);
            }
            self.complete_success();
            Ok(copied)
        }

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
                    let error = Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    };
                    self.complete_error(&error);
                    return Err(error);
                }
                collected.extend_from_slice(&chunk[..read]);
            }
            self.complete_success();
            Ok(Bytes::from(collected))
        }

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
                    let error = Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: self.method.clone(),
                        uri: self.uri_redacted.clone(),
                    };
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
                    let error = map_decode_error(error, &method, &uri_redacted, max_bytes);
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

        pub fn into_text_limited(self, max_bytes: usize) -> crate::Result<String> {
            let response = self.into_response_limited(max_bytes)?;
            response.text().map(ToOwned::to_owned)
        }

        pub fn into_text_lossy_limited(self, max_bytes: usize) -> crate::Result<String> {
            let response = self.into_response_limited(max_bytes)?;
            Ok(response.text_lossy())
        }

        pub fn into_json_limited<T>(self, max_bytes: usize) -> crate::Result<T>
        where
            T: DeserializeOwned,
        {
            let response = self.into_response_limited(max_bytes)?;
            response.json()
        }

        fn complete_success(&mut self) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.complete_success();
            }
        }

        fn complete_error(&mut self, error: &Error) {
            if let Some(lifecycle) = &mut self.lifecycle {
                lifecycle.complete_error(error);
            }
        }
    }

    impl Read for BlockingResponseStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.read_chunk(buffer).map_err(into_stream_read_io_error)
        }
    }
}

#[cfg(feature = "_blocking")]
pub use blocking_stream::BlockingResponseStream;
#[cfg(feature = "_blocking")]
pub(crate) use blocking_stream::BlockingResponseStreamContext;
#[cfg(feature = "_async")]
pub use stream::ResponseStream;
#[cfg(feature = "_async")]
pub(crate) use stream::{ResponseStreamContext, StreamPermits};
