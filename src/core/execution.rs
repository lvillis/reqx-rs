use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};

use crate::core::request_builder::RequestExecutionOptions;
use crate::error::{Error, TimeoutPhase, TransportErrorKind};
use crate::extensions::{Clock, EndpointSelector};
use crate::policy::{RedirectPolicy, RequestContext, StatusPolicy};
use crate::retry::{RetryDecision, RetryEligibility, RetryPolicy, RetryReason};
use crate::util::{
    bounded_retry_delay, deadline_exceeded_error, is_redirect_status, parse_retry_after,
    parse_retry_after_capped, phase_timeout, rate_limit_bucket_key, redact_uri_for_logs,
    redirect_location, redirect_method, resolve_redirect_uri, same_origin,
    sanitize_headers_for_redirect, total_timeout_expired, truncate_body, validate_base_url,
};

pub(crate) struct RetryRequestInput<Body> {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) redacted_uri_text: String,
    pub(crate) merged_headers: HeaderMap,
    pub(crate) body: Body,
    pub(crate) execution_options: RequestExecutionOptions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseMode {
    Buffered,
    Stream,
}

impl ResponseMode {
    pub(crate) const fn is_buffered(self) -> bool {
        matches!(self, Self::Buffered)
    }

    pub(crate) const fn is_stream(self) -> bool {
        matches!(self, Self::Stream)
    }
}

pub(crate) struct RequestExecutionStateInput {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) redacted_uri_text: String,
    pub(crate) merged_headers: HeaderMap,
    pub(crate) body_replayable: bool,
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) status_policy: StatusPolicy,
    pub(crate) timeout_value: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) request_started_at: Instant,
}

pub(crate) struct RequestExecutionState {
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) status_policy: StatusPolicy,
    pub(crate) timeout_value: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) request_started_at: Instant,
    pub(crate) attempt: usize,
    pub(crate) max_attempts: usize,
    pub(crate) redirect_count: usize,
    pub(crate) current_method: Method,
    pub(crate) current_uri: Uri,
    pub(crate) current_redacted_uri: String,
    pub(crate) current_headers: HeaderMap,
    pub(crate) body_replayable: bool,
}

impl RequestExecutionState {
    pub(crate) fn new(
        input: RequestExecutionStateInput,
        retry_eligibility: &dyn RetryEligibility,
    ) -> Self {
        let RequestExecutionStateInput {
            method,
            uri,
            redacted_uri_text,
            merged_headers,
            body_replayable,
            retry_policy,
            redirect_policy,
            status_policy,
            timeout_value,
            total_timeout,
            max_response_body_bytes,
            request_started_at,
        } = input;
        let max_attempts =
            if retry_eligibility.supports_retry(&method, &merged_headers) && body_replayable {
                retry_policy.configured_max_attempts()
            } else {
                1
            };

        Self {
            retry_policy,
            redirect_policy,
            status_policy,
            timeout_value,
            total_timeout,
            max_response_body_bytes,
            request_started_at,
            attempt: 1,
            max_attempts,
            redirect_count: 0,
            current_method: method,
            current_uri: uri,
            current_redacted_uri: redacted_uri_text,
            current_headers: merged_headers,
            body_replayable,
        }
    }

    pub(crate) const fn can_attempt(&self) -> bool {
        self.attempt <= self.max_attempts
    }

    pub(crate) fn context(&self) -> RequestContext {
        RequestContext::new(
            self.current_method.clone(),
            self.current_redacted_uri.clone(),
            self.attempt,
            self.max_attempts,
            self.redirect_count,
        )
    }

    pub(crate) fn rate_limit_host(&self) -> Option<String> {
        rate_limit_bucket_key(&self.current_uri)
    }

    pub(crate) fn phase_timeout(&self) -> Option<Duration> {
        phase_timeout(
            self.timeout_value,
            self.total_timeout,
            self.request_started_at,
        )
    }

    pub(crate) fn deadline_error(&self) -> Error {
        deadline_exceeded_error(
            self.total_timeout,
            &self.current_method,
            &self.current_redacted_uri,
        )
    }

    pub(crate) fn retry_backoff(
        &self,
        backoff_source: &dyn crate::extensions::BackoffSource,
    ) -> Duration {
        backoff_source.backoff_for_retry(&self.retry_policy, self.attempt)
    }

    pub(crate) fn status_retry_plan(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        clock: &dyn Clock,
        fallback_delay: Duration,
    ) -> StatusRetryPlan {
        status_retry_plan(StatusRetryPlanInput {
            attempt: self.attempt,
            max_attempts: self.max_attempts,
            method: &self.current_method,
            redacted_uri: &self.current_redacted_uri,
            status,
            headers,
            clock,
            fallback_delay,
            max_delay: self.retry_policy.configured_max_backoff(),
        })
    }

    pub(crate) fn retry_attempt(&mut self) -> RetryAttemptState<'_> {
        RetryAttemptState {
            retry_policy: &self.retry_policy,
            total_timeout: self.total_timeout,
            request_started_at: self.request_started_at,
            method: &self.current_method,
            redacted_uri: &self.current_redacted_uri,
            attempt: &mut self.attempt,
            max_attempts: self.max_attempts,
        }
    }

    pub(crate) fn next_redirect_action(
        &self,
        status: StatusCode,
        response_headers: &HeaderMap,
    ) -> Result<Option<RedirectAction>, Error> {
        next_redirect_action(RedirectInput {
            redirect_policy: self.redirect_policy,
            redirect_count: self.redirect_count,
            status,
            current_method: &self.current_method,
            current_uri: &self.current_uri,
            current_redacted_uri: &self.current_redacted_uri,
            response_headers,
            body_replayable: self.body_replayable,
        })
    }

    pub(crate) fn apply_redirect(
        &mut self,
        redirect_action: RedirectAction,
        retry_eligibility: &dyn RetryEligibility,
    ) -> bool {
        let drops_body = apply_redirect_transition(
            RedirectTransitionInput {
                retry_eligibility,
                retry_policy: &self.retry_policy,
                max_attempts: &mut self.max_attempts,
                body_replayable: self.body_replayable,
                current_headers: &mut self.current_headers,
                current_method: &mut self.current_method,
                current_uri: &mut self.current_uri,
                current_redacted_uri: &mut self.current_redacted_uri,
                redirect_count: &mut self.redirect_count,
            },
            redirect_action,
        );
        if drops_body {
            self.body_replayable = true;
        }
        drops_body
    }
}

#[derive(Default)]
pub(crate) struct ResponseProgress {
    ran_response_interceptors: bool,
    observed_server_throttle: bool,
    evaluated_status_retry: bool,
}

impl ResponseProgress {
    pub(crate) fn mark_response_interceptors_ran(&mut self) {
        self.ran_response_interceptors = true;
    }

    pub(crate) fn mark_server_throttle_observed(&mut self) {
        self.observed_server_throttle = true;
    }

    pub(crate) fn mark_status_retry_evaluated(&mut self) {
        self.evaluated_status_retry = true;
    }

    pub(crate) const fn needs_response_interceptors(&self) -> bool {
        !self.ran_response_interceptors
    }

    pub(crate) const fn needs_server_throttle_observation(&self) -> bool {
        !self.observed_server_throttle
    }

    pub(crate) const fn needs_status_retry_evaluation(&self) -> bool {
        !self.evaluated_status_retry
    }
}

#[derive(Debug)]
pub(crate) struct RedirectAction {
    pub(crate) next_method: Method,
    pub(crate) next_uri: Uri,
    pub(crate) next_redacted_uri: String,
    pub(crate) drops_body: bool,
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

pub(crate) fn select_base_url(
    endpoint_selector: &dyn EndpointSelector,
    method: &Method,
    path: &str,
    configured_base_url: &str,
) -> crate::Result<String> {
    let selected = endpoint_selector.select_base_url(method, path, configured_base_url)?;
    validate_base_url(&selected)?;
    Ok(selected)
}

pub(crate) fn status_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    status: StatusCode,
) -> RetryDecision {
    RetryDecision::new(
        attempt,
        max_attempts,
        method.clone(),
        redacted_uri.to_owned(),
        RetryReason::Status(status),
    )
}

pub(crate) fn transport_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    transport_error_kind: TransportErrorKind,
) -> RetryDecision {
    RetryDecision::new(
        attempt,
        max_attempts,
        method.clone(),
        redacted_uri.to_owned(),
        RetryReason::Transport(transport_error_kind),
    )
}

pub(crate) fn timeout_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
    timeout_phase: TimeoutPhase,
) -> RetryDecision {
    RetryDecision::new(
        attempt,
        max_attempts,
        method.clone(),
        redacted_uri.to_owned(),
        RetryReason::Timeout(timeout_phase),
    )
}

pub(crate) fn response_body_read_retry_decision(
    attempt: usize,
    max_attempts: usize,
    method: &Method,
    redacted_uri: &str,
) -> RetryDecision {
    RetryDecision::new(
        attempt,
        max_attempts,
        method.clone(),
        redacted_uri.to_owned(),
        RetryReason::ResponseBodyRead,
    )
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
    max_delay: Duration,
) -> Duration {
    // Keep Retry-After and fallback aligned with the configured retry delay ceiling.
    let retry_after_cap = max_delay.max(Duration::from_millis(1));
    let fallback = fallback.min(retry_after_cap);
    parse_retry_after_capped(headers, clock.now_system(), retry_after_cap).unwrap_or(fallback)
}

pub(crate) fn server_throttle_delay(
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

pub(crate) enum BodyReadOutcome {
    Body(Bytes),
    Retry(Duration),
}

pub(crate) struct RetryAttemptState<'a> {
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) request_started_at: Instant,
    pub(crate) method: &'a Method,
    pub(crate) redacted_uri: &'a str,
    pub(crate) attempt: &'a mut usize,
    pub(crate) max_attempts: usize,
}

impl RetryAttemptState<'_> {
    pub(crate) fn prepare_retry_schedule(
        self,
        retry_decision: &RetryDecision,
        requested_delay: Duration,
        consume_retry_budget: impl FnOnce(&Method, &str) -> Result<(), Error>,
    ) -> Result<RetrySchedule, Error> {
        let Self {
            retry_policy,
            total_timeout,
            request_started_at,
            method,
            redacted_uri,
            attempt,
            max_attempts,
        } = self;

        prepare_retry_schedule(
            RetryScheduleInput {
                retry_policy,
                retry_decision,
                requested_delay,
                attempt,
                max_attempts,
                total_timeout,
                request_started_at,
                method,
                redacted_uri,
            },
            || consume_retry_budget(method, redacted_uri),
        )
    }
}

pub(crate) struct BodyReadRetryContext<'a> {
    pub(crate) context: &'a RequestContext,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) request_started_at: Instant,
    pub(crate) method: &'a Method,
    pub(crate) redacted_uri: &'a str,
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) max_attempts: usize,
    pub(crate) attempt: &'a mut usize,
}

pub(crate) trait AttemptOutcome {
    fn mark_success(self);
    fn mark_failure(self);
    fn cancel(self);
}

pub(crate) struct AttemptGuards<C, A> {
    circuit: Option<C>,
    adaptive: Option<A>,
}

impl<C, A> AttemptGuards<C, A> {
    pub(crate) const fn new(circuit: Option<C>, adaptive: Option<A>) -> Self {
        Self { circuit, adaptive }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.circuit.is_none() && self.adaptive.is_none()
    }

    pub(crate) fn set_adaptive(&mut self, adaptive: Option<A>) {
        self.adaptive = adaptive;
    }

    pub(crate) fn take(&mut self) -> Self {
        Self {
            circuit: self.circuit.take(),
            adaptive: self.adaptive.take(),
        }
    }
}

impl<C, A> AttemptGuards<C, A>
where
    C: AttemptOutcome,
    A: AttemptOutcome,
{
    pub(crate) fn mark_success(&mut self) {
        if let Some(circuit) = self.circuit.take() {
            circuit.mark_success();
        }
        if let Some(adaptive) = self.adaptive.take() {
            adaptive.mark_success();
        }
    }

    pub(crate) fn mark_failure(&mut self) {
        if let Some(circuit) = self.circuit.take() {
            circuit.mark_failure();
        }
        if let Some(adaptive) = self.adaptive.take() {
            adaptive.mark_failure();
        }
    }

    pub(crate) fn cancel(&mut self) {
        if let Some(circuit) = self.circuit.take() {
            circuit.cancel();
        }
        if let Some(adaptive) = self.adaptive.take() {
            adaptive.cancel();
        }
    }

    pub(crate) fn record(&mut self, success: bool) {
        if success {
            self.mark_success();
        } else {
            self.mark_failure();
        }
    }
}

pub(crate) enum RetrySchedule {
    NotScheduled,
    Scheduled { delay: Duration },
}

impl RetrySchedule {
    pub(crate) const fn delay(self) -> Option<Duration> {
        match self {
            Self::NotScheduled => None,
            Self::Scheduled { delay } => Some(delay),
        }
    }
}

pub(crate) struct RetryScheduleInput<'a> {
    pub(crate) retry_policy: &'a RetryPolicy,
    pub(crate) retry_decision: &'a RetryDecision,
    pub(crate) requested_delay: Duration,
    pub(crate) attempt: &'a mut usize,
    pub(crate) max_attempts: usize,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) request_started_at: Instant,
    pub(crate) method: &'a Method,
    pub(crate) redacted_uri: &'a str,
}

pub(crate) fn prepare_retry_schedule(
    input: RetryScheduleInput<'_>,
    consume_retry_budget: impl FnOnce() -> Result<(), Error>,
) -> Result<RetrySchedule, Error> {
    let RetryScheduleInput {
        retry_policy,
        retry_decision,
        requested_delay,
        attempt,
        max_attempts,
        total_timeout,
        request_started_at,
        method,
        redacted_uri,
    } = input;

    if *attempt >= max_attempts || !retry_policy.should_retry_decision(retry_decision) {
        return Ok(RetrySchedule::NotScheduled);
    }

    let Some(delay) = bounded_retry_delay(requested_delay, total_timeout, request_started_at)
    else {
        return Err(deadline_exceeded_error(total_timeout, method, redacted_uri));
    };

    consume_retry_budget()?;
    *attempt += 1;
    Ok(RetrySchedule::Scheduled { delay })
}

pub(crate) struct StreamTiming {
    pub(crate) total_timeout_ms: Option<u128>,
    pub(crate) deadline_at: Option<Instant>,
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
    pub(crate) max_delay: Duration,
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
        max_delay,
    } = input;
    StatusRetryPlan {
        decision: status_retry_decision(attempt, max_attempts, method, redacted_uri, status),
        delay: status_retry_delay(clock, headers, fallback_delay, max_delay),
    }
}

pub(crate) fn stream_timing(
    total_timeout: Option<Duration>,
    request_started_at: Instant,
) -> StreamTiming {
    StreamTiming {
        total_timeout_ms: total_timeout.map(|timeout| timeout.as_millis()),
        deadline_at: total_timeout.and_then(|timeout| request_started_at.checked_add(timeout)),
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
    let drops_body = redirect_drops_body(current_method, status);
    if !body_replayable && !drops_body {
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
        drops_body,
    }))
}

fn redirect_drops_body(current_method: &Method, status: StatusCode) -> bool {
    matches!(status, StatusCode::SEE_OTHER)
        || (matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
            && *current_method == Method::POST)
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
        redirect_action.drops_body,
        redirect_action.same_origin_redirect,
    );
    let drops_body = redirect_action.drops_body;
    *current_method = redirect_action.next_method;
    *current_uri = redirect_action.next_uri;
    *current_redacted_uri = redirect_action.next_redacted_uri;
    *redirect_count = redirect_count.saturating_add(1);
    if *max_attempts == 1
        && (body_replayable || drops_body)
        && retry_eligibility.supports_retry(current_method, current_headers)
    {
        *max_attempts = retry_policy.configured_max_attempts();
    }
    drops_body
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use http::HeaderMap;
    use http::header::{HeaderName, HeaderValue};

    use super::{
        RedirectInput, RetrySchedule, RetryScheduleInput, next_redirect_action,
        prepare_retry_schedule, server_throttle_delay, status_retry_delay,
        transport_retry_decision,
    };
    use crate::error::Error;
    use crate::error::TransportErrorKind;
    use crate::extensions::SystemClock;
    use crate::policy::RedirectPolicy;
    use crate::retry::RetryPolicy;

    struct TestAttempt {
        name: &'static str,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl TestAttempt {
        fn new(name: &'static str, events: &Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                name,
                events: Arc::clone(events),
            }
        }
    }

    impl super::AttemptOutcome for TestAttempt {
        fn mark_success(self) {
            self.events
                .lock()
                .expect("lock events")
                .push(format!("{}:success", self.name));
        }

        fn mark_failure(self) {
            self.events
                .lock()
                .expect("lock events")
                .push(format!("{}:failure", self.name));
        }

        fn cancel(self) {
            self.events
                .lock()
                .expect("lock events")
                .push(format!("{}:cancel", self.name));
        }
    }

    #[test]
    fn status_retry_delay_caps_retry_after_to_max_delay() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("120"),
        );

        let delay = status_retry_delay(
            &SystemClock,
            &headers,
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(250),
        );

        assert_eq!(delay, std::time::Duration::from_millis(250));
    }

    #[test]
    fn status_retry_delay_fallback_is_clamped_to_max_delay() {
        let delay = status_retry_delay(
            &SystemClock,
            &HeaderMap::new(),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(1),
        );

        assert_eq!(delay, std::time::Duration::from_secs(1));
    }

    #[test]
    fn server_throttle_delay_uses_retry_after_without_retry_backoff_cap() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_static("120"),
        );

        let delay = server_throttle_delay(&SystemClock, &headers, Duration::from_millis(50));

        assert_eq!(delay, Duration::from_secs(120));
    }

    #[test]
    fn redirect_rejects_non_replayable_body_when_method_is_preserved() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("location"),
            HeaderValue::from_static("/next"),
        );
        let current_uri = "http://example.com/old"
            .parse()
            .expect("current URI should parse");
        let method = http::Method::GET;

        let error = next_redirect_action(RedirectInput {
            redirect_policy: RedirectPolicy::limited(1),
            redirect_count: 0,
            status: http::StatusCode::TEMPORARY_REDIRECT,
            current_method: &method,
            current_uri: &current_uri,
            current_redacted_uri: "http://example.com/old",
            response_headers: &headers,
            body_replayable: false,
        })
        .expect_err("preserving a non-replayable body should fail");

        match error {
            Error::RedirectBodyNotReplayable {
                method: error_method,
                ..
            } => assert_eq!(error_method, method),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn redirect_303_drops_non_replayable_body_even_when_method_is_get() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("location"),
            HeaderValue::from_static("/next"),
        );
        let current_uri = "http://example.com/old"
            .parse()
            .expect("current URI should parse");
        let method = http::Method::GET;

        let action = next_redirect_action(RedirectInput {
            redirect_policy: RedirectPolicy::limited(1),
            redirect_count: 0,
            status: http::StatusCode::SEE_OTHER,
            current_method: &method,
            current_uri: &current_uri,
            current_redacted_uri: "http://example.com/old",
            response_headers: &headers,
            body_replayable: false,
        })
        .expect("303 redirect should be accepted")
        .expect("303 redirect should produce an action");

        assert_eq!(action.next_method, http::Method::GET);
        assert!(action.drops_body);
    }

    #[test]
    fn redirect_303_preserves_head_method() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("location"),
            HeaderValue::from_static("/next"),
        );
        let current_uri = "http://example.com/old"
            .parse()
            .expect("current URI should parse");
        let method = http::Method::HEAD;

        let action = next_redirect_action(RedirectInput {
            redirect_policy: RedirectPolicy::limited(1),
            redirect_count: 0,
            status: http::StatusCode::SEE_OTHER,
            current_method: &method,
            current_uri: &current_uri,
            current_redacted_uri: "http://example.com/old",
            response_headers: &headers,
            body_replayable: true,
        })
        .expect("303 redirect should be accepted")
        .expect("303 redirect should produce an action");

        assert_eq!(action.next_method, http::Method::HEAD);
        assert!(action.drops_body);
    }

    #[test]
    fn prepare_retry_schedule_skips_budget_when_decision_is_not_retryable() {
        let method = http::Method::GET;
        let redacted_uri = "https://example.com";
        let mut attempt = 1;
        let retry_policy =
            RetryPolicy::standard().retryable_transport_error_kinds([TransportErrorKind::Connect]);
        let retry_decision =
            transport_retry_decision(attempt, 3, &method, redacted_uri, TransportErrorKind::Dns);
        let budget_consumed = AtomicUsize::new(0);

        let schedule = prepare_retry_schedule(
            RetryScheduleInput {
                retry_policy: &retry_policy,
                retry_decision: &retry_decision,
                requested_delay: Duration::from_millis(10),
                attempt: &mut attempt,
                max_attempts: 3,
                total_timeout: Some(Duration::from_secs(1)),
                request_started_at: Instant::now(),
                method: &method,
                redacted_uri,
            },
            || {
                budget_consumed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("schedule should not fail");

        assert!(matches!(schedule, RetrySchedule::NotScheduled));
        assert_eq!(attempt, 1);
        assert_eq!(budget_consumed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn prepare_retry_schedule_consumes_budget_and_advances_attempt() {
        let method = http::Method::GET;
        let redacted_uri = "https://example.com";
        let mut attempt = 1;
        let retry_policy = RetryPolicy::standard()
            .max_attempts(3)
            .retryable_transport_error_kinds([TransportErrorKind::Connect]);
        let retry_decision = transport_retry_decision(
            attempt,
            3,
            &method,
            redacted_uri,
            TransportErrorKind::Connect,
        );
        let budget_consumed = AtomicUsize::new(0);

        let schedule = prepare_retry_schedule(
            RetryScheduleInput {
                retry_policy: &retry_policy,
                retry_decision: &retry_decision,
                requested_delay: Duration::from_millis(10),
                attempt: &mut attempt,
                max_attempts: 3,
                total_timeout: Some(Duration::from_secs(1)),
                request_started_at: Instant::now(),
                method: &method,
                redacted_uri,
            },
            || {
                budget_consumed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect("schedule should succeed");

        assert!(matches!(
            schedule,
            RetrySchedule::Scheduled {
                delay
            } if delay == Duration::from_millis(10)
        ));
        assert_eq!(attempt, 2);
        assert_eq!(budget_consumed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn prepare_retry_schedule_skips_budget_when_deadline_prevents_retry() {
        let method = http::Method::GET;
        let redacted_uri = "https://example.com";
        let mut attempt = 1;
        let retry_policy = RetryPolicy::standard()
            .max_attempts(3)
            .retryable_transport_error_kinds([TransportErrorKind::Connect]);
        let retry_decision = transport_retry_decision(
            attempt,
            3,
            &method,
            redacted_uri,
            TransportErrorKind::Connect,
        );
        let budget_consumed = AtomicUsize::new(0);
        let request_started_at = Instant::now()
            .checked_sub(Duration::from_millis(20))
            .expect("test start time should be representable");

        let error = match prepare_retry_schedule(
            RetryScheduleInput {
                retry_policy: &retry_policy,
                retry_decision: &retry_decision,
                requested_delay: Duration::from_millis(10),
                attempt: &mut attempt,
                max_attempts: 3,
                total_timeout: Some(Duration::from_millis(5)),
                request_started_at,
                method: &method,
                redacted_uri,
            },
            || {
                budget_consumed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ) {
            Ok(_) => panic!("expired deadline should prevent retry scheduling"),
            Err(error) => error,
        };

        assert!(matches!(error, Error::DeadlineExceeded { .. }));
        assert_eq!(attempt, 1);
        assert_eq!(budget_consumed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn attempt_guards_records_both_outcomes_once() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut attempts = super::AttemptGuards::new(
            Some(TestAttempt::new("circuit", &events)),
            Some(TestAttempt::new("adaptive", &events)),
        );

        attempts.mark_failure();
        attempts.mark_success();

        assert_eq!(
            *events.lock().expect("lock events"),
            vec!["circuit:failure".to_owned(), "adaptive:failure".to_owned()]
        );
    }

    #[test]
    fn attempt_guards_take_moves_unrecorded_attempts() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut attempts = super::AttemptGuards::new(
            Some(TestAttempt::new("circuit", &events)),
            Some(TestAttempt::new("adaptive", &events)),
        );

        let mut moved = attempts.take();
        assert!(attempts.is_empty());

        moved.cancel();
        attempts.mark_failure();

        assert_eq!(
            *events.lock().expect("lock events"),
            vec!["circuit:cancel".to_owned(), "adaptive:cancel".to_owned()]
        );
    }
}
