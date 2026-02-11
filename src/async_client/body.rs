use std::convert::Infallible;
use std::error::Error as StdError;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http::{HeaderMap, Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};

pub(crate) use crate::content_encoding::{
    DecodeContentEncodingError, decode_content_encoded_body_limited,
};
use crate::error::Error;

type BoxBodyError = Box<dyn StdError + Send + Sync>;
pub(crate) type ReqBody = BoxBody<Bytes, BoxBodyError>;

pub(crate) enum RequestBody {
    Buffered(Bytes),
    Streaming(ReqBody),
}

impl RequestBody {
    pub(crate) fn empty() -> Self {
        Self::Buffered(Bytes::new())
    }
}

fn map_infallible_to_box_error(never: Infallible) -> BoxBodyError {
    match never {}
}

pub(crate) fn empty_req_body() -> ReqBody {
    Full::new(Bytes::new())
        .map_err(map_infallible_to_box_error)
        .boxed()
}

pub(crate) fn buffered_req_body(body: Bytes) -> ReqBody {
    Full::new(body).map_err(map_infallible_to_box_error).boxed()
}

pub(crate) fn stream_req_body<S, E>(stream: S) -> ReqBody
where
    S: Stream<Item = Result<Bytes, E>> + Send + Sync + 'static,
    E: StdError + Send + Sync + 'static,
{
    BodyExt::boxed(StreamBody::new(stream.map(|item| {
        item.map(Frame::data)
            .map_err(|error| Box::new(error) as BoxBodyError)
    })))
}

pub(crate) fn build_http_request(
    method: Method,
    uri: Uri,
    headers: &HeaderMap,
    body: ReqBody,
) -> Result<Request<ReqBody>, Error> {
    let mut request_builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request_builder = request_builder.header(name, value);
    }
    request_builder
        .body(body)
        .map_err(|source| Error::RequestBuild { source })
}

pub(crate) enum ReadBodyError {
    Read(hyper::Error),
    TooLarge { actual_bytes: usize },
}

pub(crate) async fn read_all_body_limited(
    mut body: Incoming,
    max_bytes: usize,
) -> Result<Bytes, ReadBodyError> {
    let mut collected = Vec::new();
    let mut total_len = 0_usize;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ReadBodyError::Read)?;
        if let Some(data) = frame.data_ref() {
            total_len = total_len.saturating_add(data.len());
            if total_len > max_bytes {
                return Err(ReadBodyError::TooLarge {
                    actual_bytes: total_len,
                });
            }
            collected.extend_from_slice(data);
        }
    }

    Ok(Bytes::from(collected))
}
