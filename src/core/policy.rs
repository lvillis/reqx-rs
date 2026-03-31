use http::{HeaderMap, Method, StatusCode};

use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Redirect handling policy.
pub struct RedirectPolicy {
    enabled: bool,
    max_redirects: usize,
}

impl RedirectPolicy {
    /// Disables automatic redirect following.
    pub const fn none() -> Self {
        Self {
            enabled: false,
            max_redirects: 0,
        }
    }

    /// Follows redirects up to `max_redirects`.
    pub const fn limited(max_redirects: usize) -> Self {
        if max_redirects == 0 {
            Self::none()
        } else {
            Self {
                enabled: true,
                max_redirects,
            }
        }
    }

    /// Follows redirects with the default limit of 10 hops.
    pub const fn follow() -> Self {
        Self::limited(10)
    }

    /// Returns whether redirect following is enabled.
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Returns the configured redirect limit.
    pub const fn max_redirects(self) -> usize {
        if self.enabled { self.max_redirects } else { 0 }
    }
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests {
    use super::RedirectPolicy;

    #[test]
    fn redirect_policy_limited_zero_is_equivalent_to_none() {
        let policy = RedirectPolicy::limited(0);
        assert!(!policy.enabled());
        assert_eq!(policy.max_redirects(), 0);
        assert_eq!(policy, RedirectPolicy::none());
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// How HTTP statuses should be surfaced to the caller.
pub enum StatusPolicy {
    #[default]
    /// Treat non-success statuses as [`Error::HttpStatus`](crate::Error::HttpStatus).
    Error,
    /// Return HTTP status responses without converting them into errors.
    Response,
}

impl StatusPolicy {
    /// Returns [`Self::Error`].
    pub const fn error() -> Self {
        Self::Error
    }

    /// Returns [`Self::Response`].
    pub const fn response() -> Self {
        Self::Response
    }

    /// Returns `true` when non-success statuses are converted into errors.
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

#[derive(Clone, Debug)]
/// Immutable request metadata passed to interceptors and observers.
pub struct RequestContext {
    method: Method,
    uri: String,
    attempt: usize,
    max_attempts: usize,
    redirect_count: usize,
}

impl RequestContext {
    pub(crate) fn new(
        method: Method,
        uri: String,
        attempt: usize,
        max_attempts: usize,
        redirect_count: usize,
    ) -> Self {
        Self {
            method,
            uri,
            attempt,
            max_attempts,
            redirect_count,
        }
    }

    /// Returns the request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request URI with the crate's redaction rules applied.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the current attempt number, starting at `1`.
    pub fn attempt(&self) -> usize {
        self.attempt
    }

    /// Returns the maximum number of attempts allowed for this request.
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Returns how many redirects have already been followed.
    pub fn redirect_count(&self) -> usize {
        self.redirect_count
    }
}

/// Active hook for mutating or observing request execution.
pub trait Interceptor: Send + Sync {
    /// Called before a request is sent. Interceptors may mutate headers.
    fn on_request(&self, _context: &RequestContext, _headers: &mut HeaderMap) {}

    /// Called after a response status and headers are received.
    fn on_response(&self, _context: &RequestContext, _status: StatusCode, _headers: &HeaderMap) {}

    /// Called when request execution ends in an error.
    fn on_error(&self, _context: &RequestContext, _error: &Error) {}
}
