use std::convert::Infallible;
use std::error::Error as StdError;
use std::io::{self, Read};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use http::header::CONTENT_ENCODING;
use http::{HeaderMap, Method, Request, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};

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

#[derive(Debug)]
pub(crate) enum DecodeContentEncodingError {
    Decode { encoding: String, message: String },
    TooLarge { actual_bytes: usize },
}

fn read_to_end_limited<R: Read>(
    reader: &mut R,
    encoding: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DecodeContentEncodingError> {
    let mut decoded = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let read = reader.read(&mut chunk).map_err(|error: io::Error| {
            DecodeContentEncodingError::Decode {
                encoding: encoding.to_owned(),
                message: error.to_string(),
            }
        })?;
        if read == 0 {
            break;
        }
        let next_size = decoded.len().saturating_add(read);
        if next_size > max_bytes {
            return Err(DecodeContentEncodingError::TooLarge {
                actual_bytes: next_size,
            });
        }
        decoded.extend_from_slice(&chunk[..read]);
    }

    Ok(decoded)
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

pub(crate) fn decode_content_encoded_body_limited(
    mut body: Bytes,
    headers: &HeaderMap,
    max_bytes: usize,
) -> Result<Bytes, DecodeContentEncodingError> {
    let max_bytes = max_bytes.max(1);
    let Some(content_encoding) = headers.get(CONTENT_ENCODING) else {
        return Ok(body);
    };
    let content_encoding =
        content_encoding
            .to_str()
            .map_err(|error| DecodeContentEncodingError::Decode {
                encoding: "content-encoding".to_owned(),
                message: error.to_string(),
            })?;
    let mut encodings = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();

    while let Some(encoding) = encodings.pop() {
        let decoded = match encoding.to_ascii_lowercase().as_str() {
            "identity" => {
                if body.len() > max_bytes {
                    return Err(DecodeContentEncodingError::TooLarge {
                        actual_bytes: body.len(),
                    });
                }
                body.to_vec()
            }
            "gzip" => {
                let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
                read_to_end_limited(&mut decoder, encoding, max_bytes)?
            }
            "deflate" => {
                let mut decoder = flate2::read::ZlibDecoder::new(body.as_ref());
                read_to_end_limited(&mut decoder, encoding, max_bytes)?
            }
            "br" => {
                let mut decoder = brotli::Decompressor::new(body.as_ref(), 4096);
                read_to_end_limited(&mut decoder, encoding, max_bytes)?
            }
            "zstd" => {
                let mut decoder =
                    zstd::stream::read::Decoder::new(body.as_ref()).map_err(|error| {
                        DecodeContentEncodingError::Decode {
                            encoding: encoding.to_owned(),
                            message: error.to_string(),
                        }
                    })?;
                read_to_end_limited(&mut decoder, encoding, max_bytes)?
            }
            other => {
                return Err(DecodeContentEncodingError::Decode {
                    encoding: other.to_owned(),
                    message: "unsupported content-encoding".to_owned(),
                });
            }
        };
        body = Bytes::from(decoded);
    }

    Ok(body)
}
