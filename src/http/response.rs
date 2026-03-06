use bytes::Bytes;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::{HeaderMap, Method, StatusCode};
use serde::de::DeserializeOwned;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use std::io;
#[cfg(any(feature = "_async", feature = "_blocking"))]
use std::time::{Duration, Instant};

#[cfg(any(feature = "_async", feature = "_blocking"))]
use crate::content_encoding::DecodeContentEncodingError;
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
pub(crate) const DEFAULT_STREAM_DEADLINE_SLACK: Duration = Duration::from_millis(1);

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_elapsed(deadline_at: Instant, now: Instant) -> bool {
    now >= deadline_at
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_limits_wait(
    phase_timeout: Duration,
    deadline_at: Instant,
    now: Instant,
) -> bool {
    deadline_at.saturating_duration_since(now) <= phase_timeout
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(crate) fn deadline_within_slack(
    deadline_at: Instant,
    now: Instant,
    deadline_slack: Duration,
) -> bool {
    deadline_at.saturating_duration_since(now) <= deadline_slack
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

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn attach_completion(
    lifecycle: &mut Option<StreamLifecycle>,
    completion: StreamCompletion,
) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.attach_completion(completion);
    } else {
        let mut new_lifecycle = StreamLifecycle::new(None);
        new_lifecycle.attach_completion(completion);
        *lifecycle = Some(new_lifecycle);
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn complete_success(lifecycle: &mut Option<StreamLifecycle>) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.complete_success();
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn complete_error(lifecycle: &mut Option<StreamLifecycle>, error: &Error) {
    if let Some(lifecycle) = lifecycle {
        lifecycle.complete_error(error);
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn map_decode_body_error(
    error: DecodeContentEncodingError,
    method: &Method,
    uri: &str,
    max_bytes: usize,
) -> Error {
    match error {
        DecodeContentEncodingError::Decode { encoding, message } => Error::DecodeContentEncoding {
            encoding,
            method: method.clone(),
            uri: uri.to_owned(),
            message,
        },
        DecodeContentEncodingError::TooLarge { actual_bytes } => Error::ResponseBodyTooLarge {
            limit_bytes: max_bytes,
            actual_bytes,
            method: method.clone(),
            uri: uri.to_owned(),
        },
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
fn stream_read_io_error_kind(error: &Error) -> io::ErrorKind {
    match error {
        Error::Timeout { .. } | Error::DeadlineExceeded { .. } => io::ErrorKind::TimedOut,
        Error::ReadBody { source } | Error::WriteBody { source, .. } => source
            .downcast_ref::<io::Error>()
            .map_or(io::ErrorKind::Other, io::Error::kind),
        _ => io::ErrorKind::Other,
    }
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn into_stream_read_io_error(error: Error) -> io::Error {
    let kind = stream_read_io_error_kind(&error);
    io::Error::new(kind, error)
}

#[cfg(any(feature = "_async", feature = "_blocking"))]
pub(super) fn write_body_error<E>(method: &Method, uri: &str, source: E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::WriteBody {
        method: method.clone(),
        uri: uri.to_owned(),
        source: Box::new(source),
    }
}

#[cfg(feature = "_async")]
mod async_stream;
#[cfg(feature = "_blocking")]
mod blocking_stream;

#[cfg(feature = "_async")]
pub use async_stream::ResponseStream;
#[cfg(feature = "_async")]
pub(crate) use async_stream::{ResponseStreamContext, StreamPermits};
#[cfg(feature = "_blocking")]
pub use blocking_stream::BlockingResponseStream;
#[cfg(feature = "_blocking")]
pub(crate) use blocking_stream::BlockingResponseStreamContext;
