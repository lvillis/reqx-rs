use bytes::Bytes;
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
    use http::{HeaderMap, StatusCode};
    use hyper::body::Incoming;

    #[derive(Debug)]
    pub struct HttpResponseStream {
        status: StatusCode,
        headers: HeaderMap,
        body: Incoming,
    }

    impl HttpResponseStream {
        pub(crate) fn new(status: StatusCode, headers: HeaderMap, body: Incoming) -> Self {
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

        pub fn into_body(self) -> Incoming {
            self.body
        }
    }
}

#[cfg(feature = "_async")]
pub use stream::HttpResponseStream;
