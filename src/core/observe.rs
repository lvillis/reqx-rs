use std::time::Duration;

use crate::policy::RequestContext;
use crate::rate_limit::ServerThrottleScope;
use crate::retry::RetryDecision;

/// Passive observer for request lifecycle events.
pub trait Observer: Send + Sync {
    /// Called when a request attempt starts.
    fn on_request_start(&self, _context: &RequestContext) {}

    /// Called when a retry has been scheduled.
    fn on_retry_scheduled(
        &self,
        _context: &RequestContext,
        _decision: &RetryDecision,
        _delay: Duration,
    ) {
    }

    /// Called when the client honors a server throttling hint.
    fn on_server_throttle(
        &self,
        _context: &RequestContext,
        _scope: ServerThrottleScope,
        _delay: Duration,
    ) {
    }
}
