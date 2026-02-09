use std::error::Error as StdError;
use std::time::Duration;

use bytes::Bytes;
use futures_core::Stream;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

use crate::body::{RequestBody, stream_req_body};
use crate::client::{HttpClient, RequestExecutionOptions};
use crate::retry::RetryPolicy;
use crate::util::{append_query_pairs, parse_header_name, parse_header_value};
use crate::{IDEMPOTENCY_KEY_HEADER, ReqxResult};

#[doc(hidden)]
pub struct RequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    path: String,
    query_pairs: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<RequestBody>,
    timeout: Option<Duration>,
    total_timeout: Option<Duration>,
    max_response_body_bytes: Option<usize>,
    retry_policy: Option<RetryPolicy>,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a HttpClient, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            query_pairs: Vec::new(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            total_timeout: None,
            max_response_body_bytes: None,
            retry_policy: None,
        }
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn try_header(self, name: &str, value: &str) -> ReqxResult<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.header(name, value))
    }

    pub fn idempotency_key(self, key: &str) -> ReqxResult<Self> {
        self.try_header(IDEMPOTENCY_KEY_HEADER, key)
    }

    pub fn query_pair(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_pairs.push((name.into(), value.into()));
        self
    }

    pub fn query_pairs<K, V, I>(mut self, pairs: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.query_pairs.extend(
            pairs
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    pub fn query<T>(mut self, params: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(params)
            .map_err(|source| crate::error::HttpClientError::SerializeQuery { source })?;
        self.query_pairs.extend(
            url::form_urlencoded::parse(encoded.as_bytes())
                .map(|(name, value)| (name.into_owned(), value.into_owned())),
        );
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(RequestBody::Buffered(body.into()));
        self
    }

    pub fn body_stream<S, E>(mut self, stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + Send + Sync + 'static,
        E: StdError + Send + Sync + 'static,
    {
        self.body = Some(RequestBody::Streaming(stream_req_body(stream)));
        self
    }

    pub fn body_reader<R>(self, reader: R) -> Self
    where
        R: AsyncRead + Send + Sync + 'static,
    {
        self.body_stream(ReaderStream::new(reader))
    }

    pub fn body_bytes(mut self, body: Bytes) -> Self {
        self.body = Some(RequestBody::Buffered(body));
        self
    }

    pub fn json<T>(self, payload: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let body = serde_json::to_vec(payload)
            .map_err(|source| crate::error::HttpClientError::Serialize { source })?;
        let with_body = self.body_bytes(Bytes::from(body));
        Ok(with_body.header(CONTENT_TYPE, HeaderValue::from_static("application/json")))
    }

    pub fn form<T>(self, payload: &T) -> ReqxResult<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(payload)
            .map_err(|source| crate::error::HttpClientError::SerializeForm { source })?;
        let with_body = self.body_bytes(Bytes::from(encoded));
        Ok(with_body.header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ))
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.max_response_body_bytes = Some(max_response_body_bytes.max(1));
        self
    }

    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = Some(retry_policy);
        self
    }

    pub async fn send(self) -> ReqxResult<crate::response::HttpResponse> {
        let path = append_query_pairs(&self.path, &self.query_pairs);
        let execution_options = RequestExecutionOptions {
            request_timeout: self.timeout,
            total_timeout: self.total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
        };
        self.client
            .send_request(
                self.method,
                path,
                self.headers,
                self.body,
                execution_options,
            )
            .await
    }

    pub async fn send_stream(self) -> ReqxResult<crate::response::HttpResponseStream> {
        let path = append_query_pairs(&self.path, &self.query_pairs);
        let execution_options = RequestExecutionOptions {
            request_timeout: self.timeout,
            total_timeout: self.total_timeout,
            max_response_body_bytes: self.max_response_body_bytes,
            retry_policy: self.retry_policy,
        };
        self.client
            .send_request_stream(
                self.method,
                path,
                self.headers,
                self.body,
                execution_options,
            )
            .await
    }

    pub async fn send_json<T>(self) -> ReqxResult<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send().await?;
        response.json()
    }
}
