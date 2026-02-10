use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;

use crate::ReqxResult;
use crate::error::HttpClientError;
use crate::util::truncate_body;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl HttpResponse {
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

    pub fn json<T>(&self) -> ReqxResult<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(&self.body).map_err(|source| HttpClientError::Deserialize {
            source,
            body: truncate_body(&self.body),
        })
    }
}

#[cfg(feature = "_async")]
mod stream {
    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use serde::de::DeserializeOwned;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use crate::ReqxResult;
    use crate::body::{
        DecodeContentEncodingError, ReadBodyError, decode_content_encoded_body_limited,
        read_all_body_limited,
    };
    use crate::error::HttpClientError;
    use crate::response::HttpResponse;

    fn map_read_body_error(
        error: ReadBodyError,
        method: &http::Method,
        uri: &str,
        max_bytes: usize,
    ) -> HttpClientError {
        match error {
            ReadBodyError::Read(source) => HttpClientError::ReadBody {
                source: Box::new(source),
            },
            ReadBodyError::TooLarge { actual_bytes } => HttpClientError::ResponseBodyTooLarge {
                limit_bytes: max_bytes,
                actual_bytes,
                method: method.clone(),
                uri: uri.to_owned(),
            },
        }
    }

    fn map_decode_body_error(
        error: DecodeContentEncodingError,
        method: &http::Method,
        uri: &str,
        max_bytes: usize,
    ) -> HttpClientError {
        match error {
            DecodeContentEncodingError::Decode { encoding, message } => {
                HttpClientError::DecodeContentEncoding {
                    encoding,
                    method: method.clone(),
                    uri: uri.to_owned(),
                    message,
                }
            }
            DecodeContentEncodingError::TooLarge { actual_bytes } => {
                HttpClientError::ResponseBodyTooLarge {
                    limit_bytes: max_bytes,
                    actual_bytes,
                    method: method.clone(),
                    uri: uri.to_owned(),
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct HttpResponseStream {
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
        method: http::Method,
        uri: String,
    }

    impl HttpResponseStream {
        pub(crate) fn new(
            status: StatusCode,
            headers: HeaderMap,
            body: Incoming,
            method: http::Method,
            uri: String,
        ) -> Self {
            Self {
                status,
                headers,
                body,
                method,
                uri,
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

        pub fn into_body(self) -> Incoming {
            self.body
        }

        pub async fn into_bytes_limited(self, max_bytes: usize) -> ReqxResult<Bytes> {
            let max_bytes = max_bytes.max(1);
            read_all_body_limited(self.body, max_bytes)
                .await
                .map_err(|error| map_read_body_error(error, &self.method, &self.uri, max_bytes))
        }

        pub async fn copy_to_writer<W>(mut self, writer: &mut W) -> ReqxResult<u64>
        where
            W: AsyncWrite + Unpin + Send + ?Sized,
        {
            let mut copied = 0_u64;

            while let Some(frame) = self.body.frame().await {
                let frame = frame.map_err(|source| HttpClientError::ReadBody {
                    source: Box::new(source),
                })?;
                if let Some(data) = frame.data_ref() {
                    writer
                        .write_all(data)
                        .await
                        .map_err(|source| HttpClientError::ReadBody {
                            source: Box::new(source),
                        })?;
                    copied = copied.saturating_add(data.len() as u64);
                }
            }
            writer
                .flush()
                .await
                .map_err(|source| HttpClientError::ReadBody {
                    source: Box::new(source),
                })?;
            Ok(copied)
        }

        pub async fn copy_to_writer_limited<W>(
            mut self,
            writer: &mut W,
            max_bytes: usize,
        ) -> ReqxResult<u64>
        where
            W: AsyncWrite + Unpin + Send + ?Sized,
        {
            let max_bytes = max_bytes.max(1);
            let mut copied = 0_u64;

            while let Some(frame) = self.body.frame().await {
                let frame = frame.map_err(|source| HttpClientError::ReadBody {
                    source: Box::new(source),
                })?;
                if let Some(data) = frame.data_ref() {
                    copied = copied.saturating_add(data.len() as u64);
                    if copied > max_bytes as u64 {
                        return Err(HttpClientError::ResponseBodyTooLarge {
                            limit_bytes: max_bytes,
                            actual_bytes: copied as usize,
                            method: self.method.clone(),
                            uri: self.uri.clone(),
                        });
                    }
                    writer
                        .write_all(data)
                        .await
                        .map_err(|source| HttpClientError::ReadBody {
                            source: Box::new(source),
                        })?;
                }
            }
            writer
                .flush()
                .await
                .map_err(|source| HttpClientError::ReadBody {
                    source: Box::new(source),
                })?;
            Ok(copied)
        }

        pub async fn into_response_limited(self, max_bytes: usize) -> ReqxResult<HttpResponse> {
            let HttpResponseStream {
                status,
                mut headers,
                body,
                method,
                uri,
            } = self;
            let max_bytes = max_bytes.max(1);
            let body = read_all_body_limited(body, max_bytes)
                .await
                .map_err(|error| map_read_body_error(error, &method, &uri, max_bytes))?;
            let body = decode_content_encoded_body_limited(body, &headers, max_bytes)
                .map_err(|error| map_decode_body_error(error, &method, &uri, max_bytes))?;
            if headers.contains_key(super::CONTENT_ENCODING) {
                headers.remove(super::CONTENT_ENCODING);
                headers.remove(super::CONTENT_LENGTH);
            }
            Ok(HttpResponse::new(status, headers, body))
        }

        pub async fn into_text_limited(self, max_bytes: usize) -> ReqxResult<String> {
            let response = self.into_response_limited(max_bytes).await?;
            Ok(response.text_lossy())
        }

        pub async fn into_json_limited<T>(self, max_bytes: usize) -> ReqxResult<T>
        where
            T: DeserializeOwned,
        {
            let response = self.into_response_limited(max_bytes).await?;
            response.json()
        }
    }
}

#[cfg(feature = "_blocking")]
mod blocking_stream {
    use std::io::{Read, Write};

    use bytes::Bytes;
    use http::{HeaderMap, StatusCode};
    use serde::de::DeserializeOwned;

    use crate::ReqxResult;
    use crate::error::{HttpClientError, TimeoutPhase};
    use crate::response::HttpResponse;

    fn map_read_error(
        source: std::io::Error,
        method: &http::Method,
        uri: &str,
        timeout_ms: u128,
    ) -> HttpClientError {
        if let Some(ureq_error) = source
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ureq::Error>())
        {
            if let ureq::Error::Timeout(timeout) = ureq_error {
                let _ = timeout;
                return HttpClientError::Timeout {
                    phase: TimeoutPhase::ResponseBody,
                    timeout_ms,
                    method: method.clone(),
                    uri: uri.to_owned(),
                };
            }

            #[cfg(any(
                feature = "blocking-tls-rustls-ring",
                feature = "blocking-tls-rustls-aws-lc-rs",
                feature = "blocking-tls-native"
            ))]
            if let ureq::Error::Decompress(encoding, decode_error) = ureq_error {
                return HttpClientError::DecodeContentEncoding {
                    encoding: encoding.to_string(),
                    method: method.clone(),
                    uri: uri.to_owned(),
                    message: decode_error.to_string(),
                };
            }
        }

        HttpClientError::ReadBody {
            source: Box::new(source),
        }
    }

    #[derive(Debug)]
    pub struct BlockingHttpResponseStream {
        status: StatusCode,
        headers: HeaderMap,
        body: ureq::Body,
        method: http::Method,
        uri: String,
        timeout_ms: u128,
    }

    impl BlockingHttpResponseStream {
        pub(crate) fn new(
            status: StatusCode,
            headers: HeaderMap,
            body: ureq::Body,
            method: http::Method,
            uri: String,
            timeout_ms: u128,
        ) -> Self {
            Self {
                status,
                headers,
                body,
                method,
                uri,
                timeout_ms,
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

        pub fn read_chunk(&mut self, buffer: &mut [u8]) -> ReqxResult<usize> {
            self.body
                .as_reader()
                .read(buffer)
                .map_err(|source| map_read_error(source, &self.method, &self.uri, self.timeout_ms))
        }

        pub fn copy_to_writer<W>(mut self, writer: &mut W) -> ReqxResult<u64>
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
                    .map_err(|source| HttpClientError::ReadBody {
                        source: Box::new(source),
                    })?;
                copied = copied.saturating_add(read as u64);
            }
            writer.flush().map_err(|source| HttpClientError::ReadBody {
                source: Box::new(source),
            })?;
            Ok(copied)
        }

        pub fn copy_to_writer_limited<W>(
            mut self,
            writer: &mut W,
            max_bytes: usize,
        ) -> ReqxResult<u64>
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
                    return Err(HttpClientError::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: copied as usize,
                        method: self.method.clone(),
                        uri: self.uri.clone(),
                    });
                }
                writer
                    .write_all(&chunk[..read])
                    .map_err(|source| HttpClientError::ReadBody {
                        source: Box::new(source),
                    })?;
            }
            writer.flush().map_err(|source| HttpClientError::ReadBody {
                source: Box::new(source),
            })?;
            Ok(copied)
        }

        pub fn into_bytes_limited(mut self, max_bytes: usize) -> ReqxResult<Bytes> {
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
                    return Err(HttpClientError::ResponseBodyTooLarge {
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

        pub fn into_response_limited(self, max_bytes: usize) -> ReqxResult<HttpResponse> {
            let BlockingHttpResponseStream {
                status,
                mut headers,
                mut body,
                method,
                uri,
                timeout_ms,
            } = self;
            let max_bytes = max_bytes.max(1);
            let mut chunk = [0_u8; 8192];
            let mut collected = Vec::new();
            let mut total_len = 0_usize;

            loop {
                let read = body
                    .as_reader()
                    .read(&mut chunk)
                    .map_err(|source| map_read_error(source, &method, &uri, timeout_ms))?;
                if read == 0 {
                    break;
                }
                total_len = total_len.saturating_add(read);
                if total_len > max_bytes {
                    return Err(HttpClientError::ResponseBodyTooLarge {
                        limit_bytes: max_bytes,
                        actual_bytes: total_len,
                        method: method.clone(),
                        uri: uri.clone(),
                    });
                }
                collected.extend_from_slice(&chunk[..read]);
            }
            let body = Bytes::from(collected);
            if headers.contains_key(super::CONTENT_ENCODING) {
                headers.remove(super::CONTENT_ENCODING);
                headers.remove(super::CONTENT_LENGTH);
            }
            Ok(HttpResponse::new(status, headers, body))
        }

        pub fn into_text_limited(self, max_bytes: usize) -> ReqxResult<String> {
            let response = self.into_response_limited(max_bytes)?;
            Ok(response.text_lossy())
        }

        pub fn into_json_limited<T>(self, max_bytes: usize) -> ReqxResult<T>
        where
            T: DeserializeOwned,
        {
            let response = self.into_response_limited(max_bytes)?;
            response.json()
        }
    }
}

#[cfg(feature = "_blocking")]
pub use blocking_stream::BlockingHttpResponseStream;
#[cfg(feature = "_async")]
pub use stream::HttpResponseStream;
