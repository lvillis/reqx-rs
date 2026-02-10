use http::{HeaderMap, Method, StatusCode};

use crate::error::HttpClientError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedirectPolicy {
    enabled: bool,
    max_redirects: usize,
}

impl RedirectPolicy {
    pub const fn none() -> Self {
        Self {
            enabled: false,
            max_redirects: 0,
        }
    }

    pub const fn limited(max_redirects: usize) -> Self {
        Self {
            enabled: true,
            max_redirects,
        }
    }

    pub const fn follow() -> Self {
        Self::limited(10)
    }

    pub const fn enabled(self) -> bool {
        self.enabled
    }

    pub const fn max_redirects(self) -> usize {
        if self.enabled { self.max_redirects } else { 0 }
    }
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::none()
    }
}

#[derive(Clone, Debug)]
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

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn attempt(&self) -> usize {
        self.attempt
    }

    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    pub fn redirect_count(&self) -> usize {
        self.redirect_count
    }
}

pub trait HttpInterceptor: Send + Sync {
    fn on_request(&self, _context: &RequestContext, _headers: &mut HeaderMap) {}

    fn on_response(&self, _context: &RequestContext, _status: StatusCode, _headers: &HeaderMap) {}

    fn on_error(&self, _context: &RequestContext, _error: &HttpClientError) {}
}
