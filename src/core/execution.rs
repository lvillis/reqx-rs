use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};

use crate::error::Error;
use crate::extensions::{Clock, EndpointSelector};
use crate::policy::StatusPolicy;
use crate::retry::RetryDecision;
use crate::util::parse_retry_after;

pub(crate) fn effective_status_policy(
    request_policy: Option<StatusPolicy>,
    client_policy: StatusPolicy,
) -> StatusPolicy {
    request_policy.unwrap_or(client_policy)
}

pub(crate) fn select_base_url(
    endpoint_selector: &dyn EndpointSelector,
    method: &Method,
    path: &str,
    configured_base_url: &str,
) -> crate::Result<String> {
    endpoint_selector.select_base_url(method, path, configured_base_url)
}

pub(crate) fn status_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    status: StatusCode,
) -> RetryDecision {
    RetryDecision {
        attempt,
        max_attempts,
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        status: Some(status),
        transport_error_kind: None,
        timeout_phase: None,
        response_body_read_error: false,
    }
}

pub(crate) fn status_retry_delay(
    clock: &dyn Clock,
    headers: &HeaderMap,
    fallback: Duration,
) -> Duration {
    parse_retry_after(headers, clock.now_system()).unwrap_or(fallback)
}

pub(crate) fn http_status_error(
    status: StatusCode,
    method: &Method,
    redacted_uri: &str,
    headers: &HeaderMap,
    body: String,
) -> Error {
    Error::HttpStatus {
        status: status.as_u16(),
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        headers: Box::new(headers.clone()),
        body,
    }
}
