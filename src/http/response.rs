use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;

use crate::error::Error;
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

#[cfg(feature = "_async")]
mod stream {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use http_body_util::BodyExt;
    use hyper::body::{Body as HyperBody, Frame, Incoming, SizeHint};
    use serde::de::DeserializeOwned;
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::time::timeout;

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

    #[derive(Debug)]
    pub struct StreamBody {
        inner: Incoming,
        _global_permit: Option<GlobalRequestPermit>,
        _host_permit: Option<HostRequestPermit>,
    }

    impl StreamBody {
        pub(crate) fn new(
            inner: Incoming,
            global_permit: Option<GlobalRequestPermit>,
            host_permit: Option<HostRequestPermit>,
        ) -> Self {
            Self {
                inner,
                _global_permit: global_permit,
                _host_permit: host_permit,
            }
        }
    }

    impl HyperBody for StreamBody {
        type Data = Bytes;
        type Error = hyper::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Pin::new(&mut self.inner).poll_frame(cx)
        }

        fn is_end_stream(&self) -> bool {
            self.inner.is_end_stream()
        }

        fn size_hint(&self) -> SizeHint {
            self.inner.size_hint()
        }
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
        pub(crate) uri: String,
        pub(crate) timeout_ms: u128,
        pub(crate) total_timeout_ms: Option<u128>,
        pub(crate) deadline_at: Option<Instant>,
        pub(crate) permits: StreamPermits,
    }

    #[derive(Debug)]
    pub struct ResponseStream {
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        method: http::Method,
        uri: String,
        timeout_ms: u128,
        total_timeout_ms: Option<u128>,
        deadline_at: Option<Instant>,
        _global_permit: Option<GlobalRequestPermit>,
        _host_permit: Option<HostRequestPermit>,
    }

    impl ResponseStream {
        pub(crate) fn new(
            status: StatusCode,
            headers: HeaderMap,
            body: Incoming,
            context: ResponseStreamContext,
        ) -> Self {
            let ResponseStreamContext {
                method,
                uri,
                timeout_ms,
                total_timeout_ms,
                deadline_at,
                permits,
            } = context;
            Self {
                status,
                headers,
                body,
                method,
                uri,
                timeout_ms: timeout_ms.max(1),
                total_timeout_ms,
                deadline_at,
                _global_permit: permits.global,
                _host_permit: permits.host,
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

        pub fn uri(&self) -> &str {
            &self.uri
        }

        pub fn into_body(self) -> StreamBody {
            StreamBody::new(self.body, self._global_permit, self._host_permit)
        }

        pub async fn into_bytes_limited(self, max_bytes: usize) -> crate::Result<Bytes> {
            let max_bytes = max_bytes.max(1);
            let mut this = self;
            this.read_raw_bytes_limited(max_bytes).await
        }

        pub async fn copy_to_writer<W>(mut self, writer: &mut W) -> crate::Result<u64>
        where
            W: AsyncWrite + Unpin + Send + ?Sized,
        {
            let mut copied = 0_u64;

            while let Some(frame) = self.next_frame_with_timeout().await? {
                if let Some(data) = frame.data_ref() {
                    writer
                        .write_all(data)
                        .await
                        .map_err(|source| Error::ReadBody {
                            source: Box::new(source),
                        })?;
                    copied = copied.saturating_add(data.len() as u64);
                }
            }
            writer.flush().await.map_err(|source| Error::ReadBody {
                source: Box::new(source),
            })?;
            Ok(copied)
        }

        pub async fn copy_to_writer_limited<W>(
            mut self,
            writer: &mut W,
            max_bytes: usize,
        ) -> crate::Result<u64>
        where
            W: AsyncWrite + Unpin + Send + ?Sized,
        {
            let max_bytes = max_bytes.max(1);
            let mut copied = 0_u64;

            while let Some(frame) = self.next_frame_with_timeout().await? {
                if let Some(data) = frame.data_ref() {
                    copied = copied.saturating_add(data.len() as u64);
                    if copied > max_bytes as u64 {
                        return Err(Error::ResponseBodyTooLarge {
                            limit_bytes: max_bytes,
                            actual_bytes: copied as usize,
                            method: self.method.clone(),
                            uri: self.uri.clone(),
                        });
                    }
                    writer
                        .write_all(data)
                        .await
                        .map_err(|source| Error::ReadBody {
                            source: Box::new(source),
                        })?;
                }
            }
            writer.flush().await.map_err(|source| Error::ReadBody {
                source: Box::new(source),
            })?;
            Ok(copied)
        }

        pub async fn into_response_limited(self, max_bytes: usize) -> crate::Result<Response> {
            let ResponseStream {
                status,
                mut headers,
                body,
                method,
                uri,
                timeout_ms,
                total_timeout_ms,
                deadline_at,
                _global_permit,
                _host_permit,
            } = self;
            let max_bytes = max_bytes.max(1);
            let mut stream = ResponseStream {
                status,
                headers: HeaderMap::new(),
                body,
                method: method.clone(),
                uri: uri.clone(),
                timeout_ms,
                total_timeout_ms,
                deadline_at,
                _global_permit,
                _host_permit,
            };
            let body = stream.read_raw_bytes_limited(max_bytes).await?;
            let should_decode = should_decode_content_encoded_body(&method, status, body.len());
            let body = if should_decode {
                decode_content_encoded_body_limited(body, &headers, max_bytes)
                    .map_err(|error| map_decode_body_error(error, &method, &uri, max_bytes))?
            } else {
                body
            };
            if should_decode && headers.contains_key(super::CONTENT_ENCODING) {
                headers.remove(super::CONTENT_ENCODING);
                headers.remove(super::CONTENT_LENGTH);
            }
            Ok(Response::new(status, headers, body))
        }

        pub async fn into_text_limited(self, max_bytes: usize) -> crate::Result<String> {
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

        fn response_body_timeout_error(&self) -> Error {
            Error::Timeout {
                phase: TimeoutPhase::ResponseBody,
                timeout_ms: self.timeout_ms.max(1),
                method: self.method.clone(),
                uri: self.uri.clone(),
            }
        }

        fn deadline_exceeded_error(&self) -> Error {
            Error::DeadlineExceeded {
                timeout_ms: self
                    .total_timeout_ms
                    .unwrap_or_else(|| self.timeout_ms.max(1)),
                method: self.method.clone(),
                uri: self.uri.clone(),
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

        async fn next_frame_with_timeout(&mut self) -> crate::Result<Option<Frame<Bytes>>> {
            let timeout_duration = self.effective_frame_timeout()?;
            let next = timeout(timeout_duration, self.body.frame())
                .await
                .map_err(|_| {
                    if self
                        .deadline_at
                        .is_some_and(|deadline_at| Instant::now() >= deadline_at)
                    {
                        self.deadline_exceeded_error()
                    } else {
                        self.response_body_timeout_error()
                    }
                })?;
            match next {
                Some(frame) => frame.map(Some).map_err(|source| Error::ReadBody {
                    source: Box::new(source),
                }),
                None => Ok(None),
            }
        }

        async fn read_raw_bytes_limited(&mut self, max_bytes: usize) -> crate::Result<Bytes> {
            let max_bytes = max_bytes.max(1);
            let mut collected = Vec::new();
            let mut total_len = 0_usize;
            while let Some(frame) = self.next_frame_with_timeout().await? {
                if let Some(data) = frame.data_ref() {
                    total_len = total_len.saturating_add(data.len());
                    if total_len > max_bytes {
                        return Err(Error::ResponseBodyTooLarge {
                            limit_bytes: max_bytes,
                            actual_bytes: total_len,
                            method: self.method.clone(),
                            uri: self.uri.clone(),
                        });
                    }
                    collected.extend_from_slice(data);
                }
            }
            Ok(Bytes::from(collected))
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

    #[derive(Debug)]
    pub struct BlockingResponseStream {
        status: StatusCode,
        headers: HeaderMap,
        body: ureq::Body,
        method: http::Method,
        uri: String,
        timeout_ms: u128,
        total_timeout_ms: Option<u128>,
        deadline_at: Option<Instant>,
    }

    #[derive(Debug)]
    pub(crate) struct BlockingResponseStreamContext {
        pub(crate) method: http::Method,
        pub(crate) uri: String,
        pub(crate) timeout_ms: u128,
        pub(crate) total_timeout_ms: Option<u128>,
        pub(crate) deadline_at: Option<Instant>,
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
                uri,
                timeout_ms,
                total_timeout_ms,
                deadline_at,
            } = context;
            Self {
                status,
                headers,
                body,
                method,
                uri,
                timeout_ms: timeout_ms.max(1),
                total_timeout_ms,
                deadline_at,
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

        pub fn uri(&self) -> &str {
            &self.uri
        }

        pub fn into_body(self) -> ureq::Body {
            self.body
        }

        pub fn read_chunk(&mut self, buffer: &mut [u8]) -> crate::Result<usize> {
            ensure_within_deadline(
                self.deadline_at,
                &self.method,
                &self.uri,
                self.timeout_ms,
                self.total_timeout_ms,
            )?;
            self.body.as_reader().read(buffer).map_err(|source| {
                map_read_error_with_deadline(
                    source,
                    &self.method,
                    &self.uri,
                    self.timeout_ms,
                    self.deadline_at,
                    self.total_timeout_ms,
                )
            })
        }

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
                writer
                    .write_all(&chunk[..read])
                    .map_err(|source| Error::ReadBody {
                        source: Box::new(source),
                    })?;
                copied = copied.saturating_add(read as u64);
            }
            writer.flush().map_err(|source| Error::ReadBody {
                source: Box::new(source),
            })?;
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
                    return Err(Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: copied as usize,
                        method: self.method.clone(),
                        uri: self.uri.clone(),
                    });
                }
                writer
                    .write_all(&chunk[..read])
                    .map_err(|source| Error::ReadBody {
                        source: Box::new(source),
                    })?;
            }
            writer.flush().map_err(|source| Error::ReadBody {
                source: Box::new(source),
            })?;
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
                    return Err(Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: self.method.clone(),
                        uri: self.uri.clone(),
                    });
                }
                collected.extend_from_slice(&chunk[..read]);
            }

            Ok(Bytes::from(collected))
        }

        pub fn into_response_limited(self, max_bytes: usize) -> crate::Result<Response> {
            let BlockingResponseStream {
                status,
                mut headers,
                mut body,
                method,
                uri,
                timeout_ms,
                total_timeout_ms,
                deadline_at,
            } = self;
            let max_bytes = max_bytes.max(1);
            let mut chunk = [0_u8; 8192];
            let mut collected = Vec::new();
            let mut total_len = 0_usize;

            loop {
                ensure_within_deadline(deadline_at, &method, &uri, timeout_ms, total_timeout_ms)?;
                let read = body.as_reader().read(&mut chunk).map_err(|source| {
                    map_read_error_with_deadline(
                        source,
                        &method,
                        &uri,
                        timeout_ms,
                        deadline_at,
                        total_timeout_ms,
                    )
                })?;
                if read == 0 {
                    break;
                }
                total_len = total_len.saturating_add(read);
                if total_len > max_bytes {
                    return Err(Error::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: method.clone(),
                        uri: uri.clone(),
                    });
                }
                collected.extend_from_slice(&chunk[..read]);
            }
            let body = Bytes::from(collected);
            let should_decode = should_decode_content_encoded_body(&method, status, body.len());
            let body = if should_decode {
                decode_content_encoded_body_limited(body, &headers, max_bytes)
                    .map_err(|error| map_decode_error(error, &method, &uri, max_bytes))?
            } else {
                body
            };
            if should_decode && headers.contains_key(super::CONTENT_ENCODING) {
                headers.remove(super::CONTENT_ENCODING);
                headers.remove(super::CONTENT_LENGTH);
            }
            Ok(Response::new(status, headers, body))
        }

        pub fn into_text_limited(self, max_bytes: usize) -> crate::Result<String> {
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
    }
}

#[cfg(feature = "_blocking")]
pub use blocking_stream::BlockingResponseStream;
#[cfg(feature = "_blocking")]
pub(crate) use blocking_stream::BlockingResponseStreamContext;
#[cfg(feature = "_async")]
pub use stream::{ResponseStream, StreamBody};
#[cfg(feature = "_async")]
pub(crate) use stream::{ResponseStreamContext, StreamPermits};
