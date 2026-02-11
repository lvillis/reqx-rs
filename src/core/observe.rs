use std::time::Duration;

use crate::policy::RequestContext;
use crate::rate_limit::ServerThrottleScope;
use crate::retry::RetryDecision;

pub trait Observer: Send + Sync {
    fn on_request_start(&self, _context: &RequestContext) {}

    fn on_retry_scheduled(
        &self,
        _context: &RequestContext,
        _decision: &RetryDecision,
        _delay: Duration,
    ) {
    }

    fn on_server_throttle(
        &self,
        _context: &RequestContext,
        _scope: ServerThrottleScope,
        _delay: Duration,
    ) {
    }
}
