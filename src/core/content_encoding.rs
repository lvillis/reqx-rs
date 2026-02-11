use std::io::{self, Read};

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use http::{Method, StatusCode};

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

pub(crate) fn should_decode_content_encoded_body(
    method: &Method,
    status: StatusCode,
    body_len: usize,
) -> bool {
    if body_len == 0 {
        return false;
    }
    if *method == Method::HEAD {
        return false;
    }
    if status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return false;
    }
    true
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
