use std::time::{Duration, Instant};

use http::{HeaderMap, Method, StatusCode, Uri};

use crate::error::{Error, TimeoutPhase, TransportErrorKind};
use crate::extensions::{Clock, EndpointSelector};
use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::retry::{RetryDecision, RetryEligibility, RetryPolicy};
use crate::util::{
    deadline_exceeded_error, is_redirect_status, parse_retry_after, redact_uri_for_logs,
    redirect_location, redirect_method, resolve_redirect_uri, same_origin,
    sanitize_headers_for_redirect, total_timeout_expired, truncate_body,
};

#[derive(Debug)]
pub(crate) struct RedirectAction {
    pub(crate) next_method: Method,
    pub(crate) next_uri: Uri,
    pub(crate) next_redacted_uri: String,
    pub(crate) method_changed_to_get: bool,
    pub(crate) same_origin_redirect: bool,
}

pub(crate) struct RedirectInput<'a> {
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) redirect_count: usize,
    pub(crate) status: StatusCode,
    pub(crate) current_method: &'a Method,
    pub(crate) current_uri: &'a Uri,
    pub(crate) current_redacted_uri: &'a str,
    pub(crate) response_headers: &'a HeaderMap,
    pub(crate) body_replayable: bool,
}

pub(crate) struct RedirectTransitionInput<'a> {
    pub(crate) retry_eligibility: &'a dyn RetryEligibility,
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) max_attempts: &'a mut usize,
    pub(crate) body_replayable: bool,
    pub(crate) current_headers: &'a mut HeaderMap,
    pub(crate) current_method: &'a mut Method,
    pub(crate) current_uri: &'a mut Uri,
    pub(crate) current_redacted_uri: &'a mut String,
    pub(crate) redirect_count: &'a mut usize,
}

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

pub(crate) fn transport_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    transport_error_kind: TransportErrorKind,
) -> RetryDecision {
    RetryDecision {
        attempt,
        max_attempts,
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        status: None,
        transport_error_kind: Some(transport_error_kind),
        timeout_phase: None,
        response_body_read_error: false,
    }
}

pub(crate) fn timeout_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    timeout_phase: TimeoutPhase,
) -> RetryDecision {
    RetryDecision {
        attempt,
        max_attempts,
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        status: None,
        transport_error_kind: None,
        timeout_phase: Some(timeout_phase),
        response_body_read_error: false,
    }
}

pub(crate) fn response_body_read_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
) -> RetryDecision {
    RetryDecision {
        attempt,
        max_attempts,
        method: method.clone(),
        uri: redacted_uri.to_owned(),
        status: None,
        transport_error_kind: None,
        timeout_phase: None,
        response_body_read_error: true,
    }
}

pub(crate) fn transport_retry_decision_from_error(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    error: &Error,
) -> Option<RetryDecision> {
    match error {
        Error::Transport { kind, .. } => Some(transport_retry_decision(
            attempt,
            max_attempts,
            method,
            redacted_uri,
            *kind,
        )),
        Error::Timeout { phase, .. } => Some(timeout_retry_decision(
            attempt,
            max_attempts,
            method,
            redacted_uri,
            *phase,
        )),
        _ => None,
    }
}

pub(crate) fn transport_timeout_error(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
    timeout_ms: u128,
    method: &Method,
    redacted_uri: &str,
) -> Error {
    if total_timeout_expired(total_timeout, request_started_at) {
        deadline_exceeded_error(total_timeout, method, redacted_uri)
    } else {
        Error::Timeout {
            phase: TimeoutPhase::Transport,
            timeout_ms,
            method: method.clone(),
            uri: redacted_uri.to_owned(),
        }
    }
}

pub(crate) fn should_mark_non_success_for_resilience(
    retry_policy: &RetryPolicy,
    status: StatusCode,
) -> bool {
    !retry_policy.is_retryable_status(status)
}

pub(crate) struct TerminalNonSuccess {
    pub(crate) error: Error,
    pub(crate) should_mark_success: bool,
}

pub(crate) fn terminal_non_success(
    status: StatusCode,
    method: &Method,
    redacted_uri: &str,
    headers: &HeaderMap,
    body: &[u8],
    retry_policy: &RetryPolicy,
) -> TerminalNonSuccess {
    TerminalNonSuccess {
        error: http_status_error(status, method, redacted_uri, headers, truncate_body(body)),
        should_mark_success: should_mark_non_success_for_resilience(retry_policy, status),
    }
}

pub(crate) fn status_retry_delay(
    clock: &dyn Clock,
    headers: &HeaderMap,
    fallback: Duration,
) -> Duration {
    parse_retry_after(headers, clock.now_system()).unwrap_or(fallback)
}

#[cfg(feature = "_async")]
pub(crate) fn status_retry_error(
    status: StatusCode,
    method: &Method,
    redacted_uri: &str,
    headers: &HeaderMap,
) -> Error {
    http_status_error(status, method, redacted_uri, headers, String::new())
}

pub(crate) const fn should_return_non_success_response(status_policy: StatusPolicy) -> bool {
    matches!(status_policy, StatusPolicy::Response)
}

pub(crate) struct StatusRetryPlan {
    pub(crate) decision: RetryDecision,
    pub(crate) delay: Duration,
}

pub(crate) struct StatusRetryPlanInput<'a> {
    pub(crate) attempt: usize,
    pub(crate) max_attempts: usize,
    pub(crate) method: &'a Method,
    pub(crate) redacted_uri: &'a str,
    pub(crate) status: StatusCode,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) clock: &'a dyn Clock,
    pub(crate) fallback_delay: Duration,
}

pub(crate) fn status_retry_plan(input: StatusRetryPlanInput<'_>) -> StatusRetryPlan {
    let StatusRetryPlanInput {
        attempt,
        max_attempts,
        method,
        redacted_uri,
        status,
        headers,
        clock,
        fallback_delay,
    } = input;
    StatusRetryPlan {
        decision: status_retry_decision(attempt, max_attempts, method, redacted_uri, status),
        delay: status_retry_delay(clock, headers, fallback_delay),
    }
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

pub(crate) fn next_redirect_action(
    redirect_input: RedirectInput<'_>,
) -> Result<Option<RedirectAction>, Error> {
    let RedirectInput {
        redirect_policy,
        redirect_count,
        status,
        current_method,
        current_uri,
        current_redacted_uri,
        response_headers,
        body_replayable,
    } = redirect_input;

    if !redirect_policy.enabled() || !is_redirect_status(status) {
        return Ok(None);
    }

    if redirect_count >= redirect_policy.max_redirects() {
        return Err(Error::RedirectLimitExceeded {
            max_redirects: redirect_policy.max_redirects(),
            method: current_method.clone(),
            uri: current_redacted_uri.to_owned(),
        });
    }

    let next_method = redirect_method(current_method, status);
    let method_changed_to_get = next_method == Method::GET && *current_method != Method::GET;
    if !body_replayable
        && !method_changed_to_get
        && !matches!(
            *current_method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        )
    {
        return Err(Error::RedirectBodyNotReplayable {
            method: current_method.clone(),
            uri: current_redacted_uri.to_owned(),
        });
    }

    let Some(location) = redirect_location(response_headers) else {
        return Err(Error::MissingRedirectLocation {
            status: status.as_u16(),
            method: current_method.clone(),
            uri: current_redacted_uri.to_owned(),
        });
    };
    let Some(next_uri) = resolve_redirect_uri(current_uri, &location) else {
        return Err(Error::InvalidRedirectLocation {
            location: redact_uri_for_logs(&location),
            method: current_method.clone(),
            uri: current_redacted_uri.to_owned(),
        });
    };

    Ok(Some(RedirectAction {
        next_method,
        same_origin_redirect: same_origin(current_uri, &next_uri),
        next_redacted_uri: redact_uri_for_logs(&next_uri.to_string()),
        next_uri,
        method_changed_to_get,
    }))
}

pub(crate) fn apply_redirect_transition(
    input: RedirectTransitionInput<'_>,
    redirect_action: RedirectAction,
) -> bool {
    let RedirectTransitionInput {
        retry_eligibility,
        retry_policy,
        max_attempts,
        body_replayable,
        current_headers,
        current_method,
        current_uri,
        current_redacted_uri,
        redirect_count,
    } = input;
    sanitize_headers_for_redirect(
        current_headers,
        redirect_action.method_changed_to_get,
        redirect_action.same_origin_redirect,
    );
    let method_changed_to_get = redirect_action.method_changed_to_get;
    *current_method = redirect_action.next_method;
    *current_uri = redirect_action.next_uri;
    *current_redacted_uri = redirect_action.next_redacted_uri;
    *redirect_count = redirect_count.saturating_add(1);
    if *max_attempts == 1
        && (body_replayable || method_changed_to_get)
        && retry_eligibility.supports_retry(current_method, current_headers)
    {
        *max_attempts = retry_policy.configured_max_attempts();
    }
    method_changed_to_get
}
