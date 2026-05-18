use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use http::{Method, StatusCode};

use crate::util::read_retry_interrupted;

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
        let read = read_retry_interrupted(reader, &mut chunk).map_err(|error| {
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

fn decode_deflate_limited(
    body: &Bytes,
    encoding: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, DecodeContentEncodingError> {
    let mut zlib_decoder = flate2::read::ZlibDecoder::new(body.as_ref());
    match read_to_end_limited(&mut zlib_decoder, encoding, max_bytes) {
        Ok(decoded) => Ok(decoded),
        Err(DecodeContentEncodingError::Decode { .. }) => {
            let mut raw_decoder = flate2::read::DeflateDecoder::new(body.as_ref());
            read_to_end_limited(&mut raw_decoder, encoding, max_bytes)
        }
        Err(error) => Err(error),
    }
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
    let mut encodings = Vec::new();
    for content_encoding in headers.get_all(CONTENT_ENCODING) {
        let content_encoding =
            content_encoding
                .to_str()
                .map_err(|error| DecodeContentEncodingError::Decode {
                    encoding: "content-encoding".to_owned(),
                    message: error.to_string(),
                })?;
        encodings.extend(
            content_encoding
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty()),
        );
    }
    if encodings.is_empty() {
        return Ok(body);
    }

    let mut encodings = encodings.into_iter().map(str::to_owned).collect::<Vec<_>>();

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
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
            }
            "deflate" => decode_deflate_limited(&body, &encoding, max_bytes)?,
            "br" => {
                let mut decoder = brotli::Decompressor::new(body.as_ref(), 4096);
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
            }
            "zstd" => {
                let mut decoder =
                    zstd::stream::read::Decoder::new(body.as_ref()).map_err(|error| {
                        DecodeContentEncodingError::Decode {
                            encoding: encoding.clone(),
                            message: error.to_string(),
                        }
                    })?;
                read_to_end_limited(&mut decoder, &encoding, max_bytes)?
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

#[cfg(test)]
mod tests {
    use std::io::{self, Read};

    use super::read_to_end_limited;

    struct InterruptedOnceReader {
        data: Vec<u8>,
        offset: usize,
        interrupted: bool,
    }

    impl InterruptedOnceReader {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                offset: 0,
                interrupted: false,
            }
        }
    }

    impl Read for InterruptedOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.offset >= self.data.len() {
                return Ok(0);
            }

            let read = buffer.len().min(self.data.len() - self.offset);
            buffer[..read].copy_from_slice(&self.data[self.offset..self.offset + read]);
            self.offset += read;
            Ok(read)
        }
    }

    #[test]
    fn read_to_end_limited_retries_interrupted_reads() {
        let mut reader = InterruptedOnceReader::new(b"decoded");
        let decoded = read_to_end_limited(&mut reader, "test", 16)
            .expect("interrupted read should be retried");

        assert_eq!(decoded, b"decoded");
    }
}
