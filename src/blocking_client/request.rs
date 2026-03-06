use std::io::Read;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::IDEMPOTENCY_KEY_HEADER;
use crate::core::request_builder::{
    PreparedRequest, RequestExecutionOverrides, RequestPreparation,
};
use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::response::{BlockingResponseStream, Response};
use crate::retry::RetryPolicy;
use crate::util::{parse_header_name, parse_header_value};

use super::{Client, RequestBody, RequestExecutionOptions};

#[doc(hidden)]
pub struct RequestBuilder<'a> {
    client: &'a Client,
    method: Method,
    path: String,
    query_pairs: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<RequestBody>,
    execution_overrides: RequestExecutionOverrides,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a Client, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            query_pairs: Vec::new(),
            headers: HeaderMap::new(),
            body: None,
            execution_overrides: RequestExecutionOverrides::default(),
        }
    }

    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn try_header(self, name: &str, value: &str) -> crate::Result<Self> {
        let name = parse_header_name(name)?;
        let value = parse_header_value(name.as_str(), value)?;
        Ok(self.header(name, value))
    }

    pub fn idempotency_key(self, key: &str) -> crate::Result<Self> {
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

    pub fn query<T>(mut self, params: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(params)
            .map_err(|source| crate::error::Error::SerializeQuery { source })?;
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

    pub fn body_reader<R>(mut self, reader: R) -> Self
    where
        R: Read + Send + 'static,
    {
        self.body = Some(RequestBody::Reader(Box::new(reader)));
        self
    }

    pub fn upload_from_reader<R>(self, reader: R) -> Self
    where
        R: Read + Send + 'static,
    {
        self.body_reader(reader)
    }

    pub fn upload_from_reader_with_length<R>(
        self,
        reader: R,
        content_length: u64,
    ) -> crate::Result<Self>
    where
        R: Read + Send + 'static,
    {
        let value = HeaderValue::from_str(&content_length.to_string()).map_err(|source| {
            crate::error::Error::InvalidHeaderValue {
                name: CONTENT_LENGTH.as_str().to_owned(),
                source,
            }
        })?;
        Ok(self.body_reader(reader).header(CONTENT_LENGTH, value))
    }

    pub fn body_bytes(mut self, body: Bytes) -> Self {
        self.body = Some(RequestBody::Buffered(body));
        self
    }

    pub fn json<T>(self, payload: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let body = serde_json::to_vec(payload)
            .map_err(|source| crate::error::Error::SerializeJson { source })?;
        let with_body = self.body_bytes(Bytes::from(body));
        Ok(with_body.header(CONTENT_TYPE, HeaderValue::from_static("application/json")))
    }

    pub fn form<T>(self, payload: &T) -> crate::Result<Self>
    where
        T: Serialize + ?Sized,
    {
        let encoded = serde_urlencoded::to_string(payload)
            .map_err(|source| crate::error::Error::SerializeForm { source })?;
        let with_body = self.body_bytes(Bytes::from(encoded));
        Ok(with_body.header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ))
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.execution_overrides.request_timeout = Some(timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn total_timeout(mut self, total_timeout: Duration) -> Self {
        self.execution_overrides.total_timeout = Some(total_timeout.max(Duration::from_millis(1)));
        self
    }

    pub fn max_response_body_bytes(mut self, max_response_body_bytes: usize) -> Self {
        self.execution_overrides.max_response_body_bytes = Some(max_response_body_bytes.max(1));
        self
    }

    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.execution_overrides.retry_policy = Some(retry_policy);
        self
    }

    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.execution_overrides.redirect_policy = Some(redirect_policy);
        self
    }

    pub fn status_policy(mut self, status_policy: StatusPolicy) -> Self {
        self.execution_overrides.status_policy = Some(status_policy);
        self
    }

    pub fn auto_accept_encoding(mut self, enabled: bool) -> Self {
        self.execution_overrides.auto_accept_encoding = Some(enabled);
        self
    }

    fn into_prepared_request(
        self,
        forced_status_policy: Option<StatusPolicy>,
    ) -> PreparedRequest<'a, Client, RequestBody, RequestExecutionOptions> {
        RequestPreparation {
            client: self.client,
            method: self.method,
            path: self.path,
            query_pairs: self.query_pairs,
            headers: self.headers,
            body: self.body,
            execution_overrides: self.execution_overrides,
        }
        .prepare(forced_status_policy, RequestExecutionOptions::from)
    }

    pub fn send(self) -> crate::Result<Response> {
        let PreparedRequest {
            client,
            method,
            path,
            headers,
            body,
            execution_options,
        } = self.into_prepared_request(None);
        client.send_request(method, path, headers, body, execution_options)
    }

    pub fn send_stream(self) -> crate::Result<BlockingResponseStream> {
        let PreparedRequest {
            client,
            method,
            path,
            headers,
            body,
            execution_options,
        } = self.into_prepared_request(None);
        client.send_request_stream(method, path, headers, body, execution_options)
    }

    pub fn download_to_writer<W>(self, writer: &mut W) -> crate::Result<u64>
    where
        W: std::io::Write + ?Sized,
    {
        self.send_stream()?.copy_to_writer(writer)
    }

    pub fn download_to_writer_limited<W>(
        self,
        writer: &mut W,
        max_bytes: usize,
    ) -> crate::Result<u64>
    where
        W: std::io::Write + ?Sized,
    {
        self.send_stream()?
            .copy_to_writer_limited(writer, max_bytes)
    }

    pub fn send_json<T>(self) -> crate::Result<T>
    where
        T: DeserializeOwned,
    {
        let response = self.send()?;
        response.json()
    }

    pub fn send_response(self) -> crate::Result<Response> {
        let PreparedRequest {
            client,
            method,
            path,
            headers,
            body,
            execution_options,
        } = self.into_prepared_request(Some(StatusPolicy::Response));
        client.send_request(method, path, headers, body, execution_options)
    }

    pub fn send_response_stream(self) -> crate::Result<BlockingResponseStream> {
        let PreparedRequest {
            client,
            method,
            path,
            headers,
            body,
            execution_options,
        } = self.into_prepared_request(Some(StatusPolicy::Response));
        client.send_request_stream(method, path, headers, body, execution_options)
    }
}

impl From<RequestExecutionOverrides> for RequestExecutionOptions {
    fn from(overrides: RequestExecutionOverrides) -> Self {
        Self {
            request_timeout: overrides.request_timeout,
            total_timeout: overrides.total_timeout,
            retry_policy: overrides.retry_policy,
            max_response_body_bytes: overrides.max_response_body_bytes,
            redirect_policy: overrides.redirect_policy,
            status_policy: overrides.status_policy,
            auto_accept_encoding: overrides.auto_accept_encoding,
        }
    }
}
