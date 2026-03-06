use std::time::Duration;

use http::{HeaderMap, Method};

use crate::policy::{RedirectPolicy, StatusPolicy};
use crate::retry::RetryPolicy;
use crate::util::append_query_pairs;

#[derive(Default)]
pub(crate) struct RequestExecutionOverrides {
    pub(crate) request_timeout: Option<Duration>,
    pub(crate) total_timeout: Option<Duration>,
    pub(crate) max_response_body_bytes: Option<usize>,
    pub(crate) retry_policy: Option<RetryPolicy>,
    pub(crate) redirect_policy: Option<RedirectPolicy>,
    pub(crate) status_policy: Option<StatusPolicy>,
    pub(crate) auto_accept_encoding: Option<bool>,
}

impl RequestExecutionOverrides {
    fn with_forced_status_policy(mut self, forced_status_policy: Option<StatusPolicy>) -> Self {
        self.status_policy = forced_status_policy.or(self.status_policy);
        self
    }
}

pub(crate) struct PreparedRequest<'a, ClientRef, Body, ExecutionOptions> {
    pub(crate) client: &'a ClientRef,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) execution_options: ExecutionOptions,
}

pub(crate) struct RequestPreparation<'a, ClientRef, Body> {
    pub(crate) client: &'a ClientRef,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) query_pairs: Vec<(String, String)>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<Body>,
    pub(crate) execution_overrides: RequestExecutionOverrides,
}

impl<'a, ClientRef, Body> RequestPreparation<'a, ClientRef, Body> {
    pub(crate) fn prepare<ExecutionOptions, F>(
        self,
        forced_status_policy: Option<StatusPolicy>,
        build_execution_options: F,
    ) -> PreparedRequest<'a, ClientRef, Body, ExecutionOptions>
    where
        F: FnOnce(RequestExecutionOverrides) -> ExecutionOptions,
    {
        PreparedRequest {
            client: self.client,
            method: self.method,
            path: append_query_pairs(&self.path, &self.query_pairs),
            headers: self.headers,
            body: self.body,
            execution_options: build_execution_options(
                self.execution_overrides
                    .with_forced_status_policy(forced_status_policy),
            ),
        }
    }
}
